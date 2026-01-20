** NIC Research 

# ENA NICs on AWS Bare Metal (Nitro): Mapping, IRQs, Queues, and Skew

On modern Nitro-based **EC2** (including bare metal), your “NICs” (Linux `eth0`, `eth1`, … devices using the **ENA** driver) are not traditional motherboard Ethernet ports. They are **PCIe devices** that represent an AWS-provided network interface implemented on **Nitro hardware**.

This README captures a practical mental model that usually matches what you see in `/proc/interrupts`, `ethtool`, and perf traces.

---

## 1) How ENA NICs map to underlying AWS hardware (Nitro)

### The pieces

- **Instance CPU/memory**
  - Bare metal: you own the whole host
  - Virtual: you are a guest

- **Nitro Card(s)**
  - Dedicated PCIe hardware that offloads networking/storage/management away from the main CPU

- **ENA device presented over PCIe**
  - On virtual instances: commonly **SR-IOV Virtual Function (VF)**
  - On bare metal: you may see something closer to a **Physical Function-like** presentation
  - Practical takeaway: it still looks like a PCIe ENA device to Linux and uses the same `ena` driver model

### What “multiple NICs” usually means on EC2

- Multiple **ENIs** (Elastic Network Interfaces) attached to the instance
- Each ENI appears as:
  - a separate Linux netdev (e.g., `eth0`, `eth1`, `ens5`, `ens6`…)
  - a separate PCI function/device
- Each ENI has:
  - its own IP(s), MAC, security group attachment
  - its own RX/TX queues (subject to instance limits)

**Rough mapping:**

> Linux netdev (`ensX`) → PCIe ENA function → queues/rings on ENA → Nitro card firmware → AWS VPC fabric

---

## 2) How IRQs are handled for ENA on Linux

ENA is a **multi-queue** NIC. Linux uses **MSI-X** interrupts so each queue (or queue-pair) can signal the CPU efficiently.

### Key ENA interrupt detail

- **ENA assigns one MSI-X vector per queue pair (RX+TX together)**
- Plus **one extra management vector**

So if you configure (say) 16 queue pairs, you usually expect:
- ~16 “I/O” interrupt lines
- +1 management interrupt line
for that ENA device.

### What happens on packet receive

1. NIC **DMA**’s packets into an RX ring buffer for a specific queue
2. NIC raises the **MSI-X interrupt** for that queue pair
3. Linux driver schedules **NAPI** polling for that queue  
   - Under load, NAPI polls in batches to reduce interrupt overhead

### Why affinity matters

- `irqbalance` may spread load in a way that’s suboptimal for NUMA / isolated CPU setups
- Manual pinning (`/proc/irq/*/smp_affinity_list`) can be great, or can accidentally funnel too much to one CPU set

---

## 3) How NIC queuing works (RX, TX, and “where queues live”)

### RX (Receive) queuing: RSS + per-queue IRQs

Linux typically uses **RSS** (Receive Side Scaling):

- NIC hashes packet headers (often 5-tuple)
- Assigns each flow to an RX queue
- Each RX queue has its own MSI-X IRQ → parallel receive across CPUs

**Practical implication:**  
A small number of “elephant flows” can land on one RSS queue → one IRQ/CPU runs hot even if the NIC has many queues.

### TX (Transmit) queuing: qdisc + per-queue TX rings

Typical transmit path:

> socket → TCP small queues / BQL / qdisc → driver selects TX queue → DMA descriptors → NIC sends

ENA has multiple TX rings, often paired with RX rings (queue pairs).

### Queue counts and distribution across ENIs

AWS notes:
- Queue limits are **instance-type dependent**
- Some instances allow dynamic allocation of ENA queues across ENIs up to instance limits

So if `eth0` has more queues than `eth1`, it can appear “busier” (more interrupts, more parallelism).

---

## 4) Why you might see disproportionate traffic on one NIC vs another

There are two common categories:

- **A) Skew across ENIs/NICs** (e.g., `ens5` vs `ens6`)
- **B) Skew across queues/IRQs on one ENI** (e.g., one RX queue/CPU hot)

### A) Skew across ENIs (ens5 vs ens6)

Common causes:

1. **Routing + source IP selection (most common)**
   - Default route often points to one interface → most outbound uses that interface
   - Replies often return via the interface owning the source IP

2. **Traffic is addressed to that ENI**
   - Inbound arrives on whichever ENI/IP clients target (DNS/config often points to one)

3. **Bonding expectations don’t apply**
   - Adding ENIs doesn’t automatically load-balance like on-prem LACP bonding

4. **Security groups/NACLs/subnets differ**
   - Different subnets/SGs/route tables can make one ENI “the only usable path”

5. **NUMA locality (common on bare metal)**
   - PCIe device can be closer to one socket
   - App threads pinned “wrong” can bias toward one NIC or make one perform better

### B) Skew within one ENI (queues / IRQs)

1. **RSS hash collisions / elephant flows**
   - One large flow maps to one RX queue → one MSI-X vector hammered

2. **IRQ affinity / irqbalance interactions**
   - Too many queue IRQs pinned to too few CPUs → backlog, drops, high softirq

3. **RPS/RFS/XPS settings**
   - Software steering can concentrate work unexpectedly

---

## 5) Quick “what to check” commands

### Map NICs to PCI + confirm ENA


Queue counts
lspci -nn | egrep -i 'ethernet|amazon|ena'
ethtool -i eth0

ethtool -l eth0
ethtool -S eth0 | egrep -i 'rx.*queue|tx.*queue|drop|err'

Queue counts
ethtool -l eth0
ethtool -S eth0 | egrep -i 'rx.*queue|tx.*queue|drop|err'
Per-queue IRQ load
cat /proc/interrupts | egrep -i 'ena|eth0|eth1'
Which NIC is used for a destination?
ip route get <DEST_IP>
ip rule show
ip route show table all
Per-NIC throughput
ip -s link show eth0

or
sar -n DEV 1

## 6) Script: Demonstrate mapping (netdev → PCI → MSI-X IRQs → queues → RSS → routing)
Save as nic_mapping_report.sh, then:
```
chmod +x nic_mapping_report.sh
./nic_mapping_report.sh
./nic_mapping_report.sh --dest 1.1.1.1 --dest 8.8.8.8
./nic_mapping_report.sh --stats
```
```
#!/usr/bin/env bash
set -euo pipefail

# nic_mapping_report.sh
# Demonstrate mapping: netdev -> PCI -> driver -> NUMA -> MSI-X IRQs -> queues -> RSS -> routing
#
# Usage:
#   ./nic_mapping_report.sh
#   ./nic_mapping_report.sh --dest 1.1.1.1 --dest 8.8.8.8
#   ./nic_mapping_report.sh --stats
#
# Notes:
# - Tries to use: ip, ethtool, lspci. Works best with ethtool + pciutils installed.
# - Does not modify any settings.

DESTS=()
SHOW_STATS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest)
      DESTS+=("${2:-}")
      shift 2
      ;;
    --stats)
      SHOW_STATS=1
      shift
      ;;
    -h|--help)
      sed -n '1,80p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 1
      ;;
  esac
done

if [[ ${#DESTS[@]} -eq 0 ]]; then
  # Common probes: public DNS, google, and IMDS
  DESTS=("1.1.1.1" "8.8.8.8" "169.254.169.254")
fi

have() { command -v "$1" >/dev/null 2>&1; }

hr() { printf '%*s\n' "${COLUMNS:-100}" '' | tr ' ' '-'; }

headline() { hr; echo "$1"; hr; }

readlink_base() {
  local p="$1"
  if [[ -e "$p" ]]; then
    basename "$(readlink -f "$p")"
  else
    echo "-"
  fi
}

sysval() {
  local f="$1"
  if [[ -r "$f" ]]; then
    cat "$f"
  else
    echo "-"
  fi
}

headline "System overview"
echo "Host:   $(hostname)"
echo "Kernel: $(uname -r)"
echo "CPU sockets/NUMA (if available):"
if have lscpu; then
  lscpu | egrep -i 'Socket|NUMA|Model name|CPU\(s\)' || true
else
  echo "  lscpu not found"
fi
echo

headline "Interfaces detected"
mapfile -t IFACES < <(ls -1 /sys/class/net | grep -vE '^(lo)$' | sort)
if [[ ${#IFACES[@]} -eq 0 ]]; then
  echo "No interfaces found (other than lo)."
  exit 0
fi
for IF in "${IFACES[@]}"; do echo " - $IF"; done
echo

for IF in "${IFACES[@]}"; do
  headline "Mapping for interface: $IF"

  echo "[A] Basic link info"
  if have ip; then
    ip -br link show dev "$IF" || true
    ip -br addr show dev "$IF" || true
  else
    echo "ip not found"
  fi
  echo

  echo "[B] sysfs -> PCI / driver / NUMA"
  DEV_PATH="/sys/class/net/${IF}/device"
  if [[ -e "$DEV_PATH" ]]; then
    PCI_BDF="$(basename "$(readlink -f "$DEV_PATH")")"
    DRIVER="$(readlink_base "$DEV_PATH/driver")"
    NUMA="$(sysval "$DEV_PATH/numa_node")"
    VENDOR="$(sysval "$DEV_PATH/vendor")"
    DEVICE="$(sysval "$DEV_PATH/device")"

    echo "PCI BDF:    $PCI_BDF"
    echo "Driver:     $DRIVER"
    echo "NUMA node:  $NUMA"
    echo "PCI IDs:    vendor=$VENDOR device=$DEVICE"

    if have lspci; then
      echo
      echo "lspci summary:"
      lspci -s "$PCI_BDF" -nn || true
    else
      echo "lspci not found (install pciutils for richer PCI info)."
    fi
  else
    echo "No device backing for $IF (may be virtual/bridge). Skipping PCI mapping."
    continue
  fi
  echo

  echo "[C] RX/TX queues present (sysfs)"
  QUEUE_DIR="/sys/class/net/${IF}/queues"
  if [[ -d "$QUEUE_DIR" ]]; then
    RXQ_COUNT="$(ls -1 "$QUEUE_DIR" 2>/dev/null | grep -c '^rx-' || true)"
    TXQ_COUNT="$(ls -1 "$QUEUE_DIR" 2>/dev/null | grep -c '^tx-' || true)"
    echo "RX queues: $RXQ_COUNT"
    echo "TX queues: $TXQ_COUNT"
    echo
    echo "Per-queue RPS/XPS (non-empty masks only):"
    for q in "$QUEUE_DIR"/rx-*; do
      [[ -e "$q" ]] || continue
      qn="$(basename "$q")"
      mask="$(sysval "$q/rps_cpus")"
      [[ "$mask" != "-" && "$mask" != "0" && "$mask" != "00000000" ]] && echo "  $qn rps_cpus=$mask"
    done
    for q in "$QUEUE_DIR"/tx-*; do
      [[ -e "$q" ]] || continue
      qn="$(basename "$q")"
      mask="$(sysval "$q/xps_cpus")"
      [[ "$mask" != "-" && "$mask" != "0" && "$mask" != "00000000" ]] && echo "  $qn xps_cpus=$mask"
    done
  else
    echo "No queue directory found."
  fi
  echo

  echo "[D] MSI-X IRQs for this PCI device (maps IRQ load + CPU affinity)"
  MSI_DIR="/sys/bus/pci/devices/${PCI_BDF}/msi_irqs"
  if [[ -d "$MSI_DIR" ]]; then
    mapfile -t IRQs < <(ls -1 "$MSI_DIR" 2>/dev/null | sort -n || true)
    if [[ ${#IRQs[@]} -eq 0 ]]; then
      echo "No MSI IRQs exposed under $MSI_DIR"
    else
      echo "MSI IRQs (sorted). NOTE: ENA typically uses one vector per queue-pair + management."
      idx=0
      for irq in "${IRQs[@]}"; do
        intr_line="$(awk -v n="$irq" '$1 ~ ("^"n":") {print; found=1} END{if(!found) print ""}' /proc/interrupts)"
        aff="$(sysval "/proc/irq/${irq}/smp_affinity_list")"
        act="$(sysval "/proc/irq/${irq}/actions")"
        echo "  [vector#${idx}] irq=${irq}  affinity=${aff}  actions=${act}"
        if [[ -n "$intr_line" ]]; then
          echo "    /proc/interrupts: $intr_line"
        fi
        idx=$((idx+1))
      done
    fi
  else
    echo "No MSI IRQ directory at $MSI_DIR"
  fi
  echo

  echo "[E] RSS indirection table -> queue distribution (shows why one queue/CPU can run hot)"
  if have ethtool && have python3; then
    python3 - "$IF" <<'PY'
import re, subprocess, sys
iface = sys.argv[1]
try:
  out = subprocess.check_output(["ethtool", "-x", iface], text=True, stderr=subprocess.STDOUT)
except Exception as e:
  print(f"ethtool -x failed: {e}")
  sys.exit(0)

nums = []
for line in out.splitlines():
  m = re.match(r'^\s*\d+\s*:\s*(.*)$', line)
  if not m:
    continue
  for tok in m.group(1).split():
    if tok.isdigit():
      nums.append(int(tok))

if not nums:
  print("No indirection entries parsed (driver may not expose RSS table).")
  sys.exit(0)

from collections import Counter
c = Counter(nums)
total = len(nums)
print(f"RSS indirection entries: {total}")
print("Queue -> % of table (bigger % can mean more flows land there):")
for q, cnt in sorted(c.items()):
  pct = (cnt/total)*100.0
  print(f"  queue {q:>3}: {cnt:>4} entries  ({pct:6.2f}%)")

print("\nRaw ethtool -x header (first ~15 lines):")
for line in out.splitlines()[:15]:
  print(line)
PY
  else
    echo "Need ethtool + python3 to view RSS/queue config."
  fi
  echo

  echo "[F] Optional: NIC counters (drops/errors/queue stats) via ethtool -S"
  if [[ "$SHOW_STATS" -eq 1 ]]; then
    if have ethtool; then
      ethtool -S "$IF" 2>/dev/null | egrep -i 'drop|err|timeout|reset|rx_queue|tx_queue|miss|buf' || true
    else
      echo "ethtool not found"
    fi
  else
    echo "Skipped (run with --stats to include)."
  fi
  echo

  echo "[G] Routing demonstration: which NIC would be used for some destinations?"
  if have ip; then
    for d in "${DESTS[@]}"; do
      echo "  ip route get $d:"
      ip route get "$d" 2>/dev/null | sed 's/^/    /' || echo "    (route lookup failed)"
    done
  else
    echo "ip not found"
  fi

  echo
done

headline "Done"
echo "Tip: If one NIC is disproportionately busy, compare:"
echo " - ip route get <dest> (egress selection)"
echo " - RSS queue histogram + /proc/interrupts (queue/IRQ skew)"
echo " - IRQ affinity (smp_affinity_list) vs your CPU pinning/isolcpus"
```

## 7) What “open fabric layer” is (and when it matters)
“Open fabric layer” usually refers to OpenFabrics Interfaces (OFI) / libfabric, and sometimes the broader OpenFabrics/RDMA stack.

Key point: it’s not part of the normal ENA (Ethernet) socket path.
It’s more commonly used with EFA (Elastic Fabric Adapter) for HPC/MPI style networking.

Where it sits
Normal ENA path (typical TCP/UDP apps):
App → sockets → Linux TCP/IP stack → qdisc → ENA driver → Nitro → VPC fabric
OpenFabrics / OFI path (often with EFA for HPC):

App/MPI/NCCL → libfabric (OFI API) → EFA provider → EFA device → AWS fabric

So if you’re debugging ENA IRQ skew, “OpenFabrics” is usually not in the datapath unless you’re actually using EFA/libfabric.

8) ENA device numbering: AWS vs Linux
There are two numbering systems people mix up:
AWS numbering (control plane)
DeviceIndex: attachment order

0 = primary ENI

1,2,… = secondary ENIs in attach order

NetworkCardIndex: which physical “network card” (on some high-bandwidth instances)

Linux interface naming
eth0, eth1 = probe/discovery order (can change)
ens5, enp0s5, etc. = predictable names derived from PCI topology
Important: ens5 does not mean ENI #5. It usually reflects PCI “slot-ish” topology in predictable naming.
Reliable ENI ↔ Linux mapping method
Use MAC address:

Linux interface → MAC:

ip -br link

IMDS MAC → ENI + device-number:

BASE=http://169.254.169.254/latest/meta-data/network/interfaces/macs
curl -s $BASE/ | tr -d '/' | while read mac; do
  echo "MAC=$mac"
  echo -n "  device-number: "; curl -s $BASE/$mac/device-number; echo
  echo -n "  interface-id:  "; curl -s $BASE/$mac/interface-id; echo
done
Linux interface → PCI BDF:

IF=ens5
readlink -f /sys/class/net/$IF/device
ethtool -i $IF | egrep 'driver|bus-info'
## 9) Confirming SR-IOV (and why “PF?” can happen)
Quick checks

AWS-side: EnaSupport=true indicates enhanced networking (AWS states this uses SR-IOV under the hood).

Host-side: VFs usually show a physfn symlink in sysfs.

Your observed output
IFACE  DRIVER  BDF            VF?  NUMA  EXTRA
ens5   ena     0000:00:05.0   PF?  -1
ens6   ena     0000:00:06.0   PF?  -1
ens7   ena     0000:00:07.0   PF?  -1
Interpretation:

You are definitely using ENA and real PCIe functions.

The script marked PF? because it did not see /sys/bus/pci/devices/<BDF>/physfn.

On Nitro (especially bare metal), it’s common that PF↔VF relationships are not exposed in a way Linux can prove from inside the instance, even if SR-IOV is used under the hood.

NUMA=-1 means “NUMA node not reported/exposed” (not necessarily a problem).

PF-style SR-IOV capability evidence (best-effort)
for bdf in 0000:00:05.0 0000:00:06.0 0000:00:07.0; do
  echo "== $bdf =="
  sudo lspci -vv -s "$bdf" | grep -i -A3 -B2 'SR-IOV' || echo "  (no SR-IOV capability shown)"
done
And check for sysfs SR-IOV knobs:

for bdf in 0000:00:05.0 0000:00:06.0 0000:00:07.0; do
echo “== $bdf ==”
for f in sriov_totalvfs sriov_numvfs; do
if [[ -r /sys/bus/pci/devices/$bdf/$f ]]; then
echo " $f=$(cat /sys/bus/pci/devices/$bdf/$f)"
else
echo " $f=not-present"
fi
done
done

## 10) Diagrams: relationships and where skew happens
Diagram 1: ENI → Linux → PCIe → Nitro → AWS fabric
AWS CONTROL PLANE (VPC)
```
┌─────────────────────────────────────────────┐
│ ENI (eni-…)                                 │
│ - Subnet / SG / routes / IPs / MAC          │
│ - Attachment: DeviceIndex (0,1,2…)          │
└───────────────────────┬─────────────────────┘
                        │ attach
                        v
┌───────────────────────────────────────────────────────────────┐
│ EC2 INSTANCE (your Linux OS)                                  │
│                                                               │
│ Linux netdev: ens5 / ens6 / ens7                              │
│ - Name from predictable naming (PCI topology)                 │
│ - MAC/IP match the ENI                                        │
│                        │                                      │
│                        v                                      │
│ ENA driver (ena.ko)                                           │
│ - multi-queue RX/TX rings                                     │
│ - RSS hashes flows → RX queue                                 │
│                        │                                      │
│                        v                                      │
│ PCIe function (what you saw):                                 │
│ ens5 → 0000:00:05.0 ens6 → 0000:00:06.0 ens7 → 00:07.0        │
└───────────────┬───────────────────────────────────────────────┘
                │ PCIe link
                v
┌───────────────────────────────────────────────────────────────┐
│ AWS NITRO HARDWARE (cards/controllers)                        │
│ - implements ENA device model over PCIe                       │
│ - offload + isolation + DMA to instance memory                │
│ - virtualization (often SR-IOV under the hood)                │
└───────────────┬───────────────────────────────────────────────┘
                │ 
                v
AWS DATACENTER NETWORK FABRIC (VPC dataplane)
```
Diagram 2: RSS → queues → MSI-X IRQs → CPU affinity (hot queue/hot CPU)
(for one interface: ens5)
```
ENA device (PCI 0000:00:05.0)
│
├─ RSS hash (5-tuple)
│ ├─ Flow A ───────────────┐
│ ├─ Flow B ───────┐       │
│ └─ Flow C ───┐   │       │
│              v   v       v
│        RX q0 RX q1 RX q2 … RX qN
│         │     │     │      │
│     MSI-X IRQ MSI-X IRQ MSI-X IRQ MSI-X IRQ
│        irq#100 irq#101 irq#102 irq#10X
│           │      │         │      │
│ smp_affinity smp_aff. smp_aff. smp_aff.
│         CPU2    CPU3     CPU10   CPU11
│           │      │         │       │
└───────── NAPI poll batches packets from each queue
```
Why skew happens

One “elephant” flow maps to one RSS queue → one IRQ/CPU looks hot

IRQ affinity / irqbalance / CPU pinning can concentrate many queues onto few CPUs

Diagram 3: ENI-level skew (why one NIC is busier)
Linux routing / policy routing decides egress per destination
```
┌──────────────────────────────────────────────────────────┐
│ ip route / ip rule choose interface + source IP          │
└──────────────┬───────────────────────────────┬───────────┘
               │                               │
               v                               v
ens5 (ENI A)                            ens6 (ENI B)
default route?                       used only for specific subnet?
peers target ENI A IP?                  peers never hit ENI B?
source IP selection SG/NACL differences
│                                               │
└──→ disproportionate traffic on ens5 can be expected
```
