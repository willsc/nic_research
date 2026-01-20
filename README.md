# nic_research

Explain to me how nics ie ena on an baremetal aws instance map to the underlying aws hardware and how are irqs handled and how is nic queuing handled. And why might we see a disproportionate amount of traffic going down on nic vs another? Thought for 1m 1s

On modern Nitro-based **EC2** (including bare metal), your “NICs” (the Linux eth0, eth1, … devices using the **ENA** driver) are not traditional motherboard Ethernet ports. They’re PCIe devices that represent an **AWS**-provided network interface implemented on Nitro hardware.

Below is the mental model that usually matches what you see in /proc/interrupts, ethtool, and perf traces.

1. How **ENA** NICs map to the underlying **AWS** hardware (Nitro)
The pieces

Your instance **CPU**/memory (bare metal: you own the whole host; virtual: you’re a guest).

Nitro Card(s): dedicated PCIe hardware that offloads networking/storage/management away from the main **CPU**.

**ENA** device presented over PCIe:

On virtualized instances it’s typically presented as an SR-**IOV** Virtual Function (VF).

On bare metal you can be closer to a Physical Function (PF) presentation (**AWS**’ Nitro design docs discuss PF vs VF for Nitro-presented devices; the practical takeaway is: it still looks like a PCIe **ENA** device and uses the same Linux **ENA** driver model).

What “multiple NICs” usually means on **EC2**

Multiple ENIs (Elastic Network Interfaces) attached to the instance, each showing up as a separate netdev (e.g. eth0, eth1) and separate **PCI** function/device.

Each **ENI** has:

its own IP(s), **MAC**, security group attachment,

its own set of RX/TX queues (subject to instance limits).

So the mapping is roughly: Linux netdev (ethX) → PCIe **ENA** function → queues/rings on **ENA** → Nitro card firmware → **AWS** **VPC** fabric

2. How IRQs are handled for **ENA** on Linux

**ENA** is a multi-queue **NIC**. Linux will use **MSI**-X interrupts so each queue (or queue-pair) can signal the **CPU** efficiently.

Key **ENA** detail (very useful when reading /proc/interrupts):

**ENA** assigns one **MSI**-X vector per queue pair (RX+TX together), plus an extra management vector.

So if you configure (say) 16 queue pairs, you should expect ~16 “I/O” interrupt lines + 1 management line for that **ENA** device.

What happens when packets arrive:

**NIC** **DMA**’s packets into an RX ring buffer for a particular queue.

**NIC** raises the **MSI**-X interrupt for that queue-pair.

Linux driver schedules **NAPI** polling for that queue (so under load it reduces interrupt rate and polls in batches).

Affinity matters a lot:

irqbalance may spread or may do something suboptimal for **NUMA**/isolcpus setups.

Manual pinning via /proc/irq/*/smp_affinity_list can be great or can accidentally funnel too much to one **CPU**.

3. How **NIC** queuing works (RX, TX, and “where queues live”)
RX (Receive) queuing: **RSS** and per-queue IRQs

Linux typically uses **RSS** (Receive Side Scaling):

**NIC** hashes packet headers (often 5-tuple) and assigns each flow to an RX queue.

Each RX queue has its own **IRQ**/**MSI**-X, enabling parallel receive on multiple CPUs.

Practical implication:

A small number of “elephant flows” can land on one **RSS** queue → you’ll see one **IRQ**/**CPU** hotter than the rest even though the **NIC** has many queues.

TX (Transmit) queuing: qdisc + per-queue TX rings

Transmit path is typically:

socket → **TCP** small queues / **BQL** / qdisc → driver picks a TX queue → **DMA** descriptors on that TX ring → **NIC** sends **ENA** (like most modern NICs) has multiple TX rings, often paired with RX rings (queue pairs).

**AWS** also documents cases (**ENA** Express) where **TCP** queue limits / byte queue limits can matter for throughput/latency tuning.

Queue counts and distribution across ENIs

**AWS** explicitly calls out:

Queue limits are instance-type dependent

On some instances you can dynamically allocate **ENA** queues across ENIs up to instance limits.

So if eth0 has more queues than eth1, it can also “look” busier (more interrupts, more parallelism).

4. Why you might see disproportionate traffic on one **NIC** vs another

There are two common cases: (A) skew across ENIs/NICs and (B) skew across queues/IRQs on a single **NIC**.

- Skew across ENIs (eth0 vs eth1)

1. Routing + source IP selection (most common)
Linux chooses an egress interface based on the routing table (and policy routing).

If your default route points to eth0, almost everything outbound will use eth0.

Replies usually return via the interface that owns the source IP (and conntrack enforces symmetry for many flows).

2. The traffic is literally addressed to that **ENI**
Inbound traffic arrives on the **ENI**/IP that clients target. If **DNS** / configs / peers point at eth0’s IP, eth1 will be quiet.

3. “Bonding” expectations that don’t apply
People expect two NICs to “share load” like **LACP**. In **AWS**, you typically don’t get switch-side **LACP** across ENIs in the way you would on-prem, so you don’t automatically get balanced utilization just by adding another **ENI**.

4. Security groups/NACLs/allowed paths differ
If eth1 is in a different subnet, has different SGs, or different route tables, the usable traffic set can be different (so skew is expected).

5. **NUMA** locality (common on bare metal)
On dual-socket bare metal, a PCIe device is physically closer to one **NUMA** node.
If your app threads are pinned to the “wrong” socket, you can end up effectively preferring one **NIC** (lower cost path), or you overload one due to affinity choices.

- Skew across queues / IRQs on the same **ENI**

1. **RSS** hash collisions / elephant flows
One big **TCP**/**UDP** flow maps to one RX queue → one **MSI**-X **IRQ** line gets hammered. This is normal with **RSS**.

2. **IRQ** affinity / irqbalance interactions
If multiple queue IRQs all end up pinned to a small **CPU** set (or a **CPU** that’s busy), you’ll see backlog, drops, higher softirq time, and “hot” queues.

3. **RPS**/**RFS**/**XPS** settings
Software steering can override where packets are processed, sometimes concentrating work unexpectedly.

5. Quick “what to check” commands (to prove which case you’re in)

Map NICs to **PCI** + confirm **ENA**

lspci -nn | egrep -i 'ethernet|amazon|ena'

ethtool -i eth0

Queue counts

ethtool -l eth0 (channels/queues)

ethtool -S eth0 | egrep -i 'rx.*queue|tx.*queue|drop|err'

See per-queue **IRQ** load

cat /proc/interrupts | egrep -i 'ena|eth0|eth1'

See which **NIC** is actually used for destinations

ip route get <DEST_IP>

ip rule show; ip route show table all

See per-**NIC** throughput

sar -n **DEV** 1 or ip -s link show eth0

If you paste:

ip route show, ip rule show

ethtool -l eth0; ethtool -l eth1

the ena lines from /proc/interrupts

…I can tell you pretty quickly whether you’re seeing routing skew (**ENI**-level) vs **RSS**/affinity skew (queue-level) and what to change first.

Can you write a script to demonstrate the mapping? Thought for 49s

Here’s a single self-contained script you can run on an **AWS** bare-metal (or normal **EC2**) Linux box to demonstrate the mapping:

netdev (eth0, eth1, …) → PCIe device (Nitro/**ENA**)

PCIe device → **MSI**-X IRQs

IRQs → **CPU** affinity

netdev → RX/TX queues

**RSS** indirection table → which queues get which flows

route selection → which **NIC** gets used for specific destinations

Save as nic_mapping_report.sh, chmod +x, run.

#!/usr/bin/env bash set -euo pipefail

# nic_mapping_report.sh

# Demonstrate mapping: netdev -> PCI -> driver -> NUMA -> MSI-X IRQs -> queues -> RSS -> routing # # Usage: #   ./nic_mapping_report.sh #   ./nic_mapping_report.sh --dest 1.1.1.1 --dest 8.8.8.8 #   ./nic_mapping_report.sh --stats # # Notes: # - Tries to use: ip, ethtool, lspci. Works best with ethtool + pciutils installed. # - Does not modify any settings.

**DESTS**=() SHOW_STATS=0

while [[ $# -gt 0 ]]; do
    case *$1* in
    --dest)
    **DESTS**+=(*${2:-}*)
    shift 2
    ;;
    --stats)
    SHOW_STATS=1
    shift
    ;;
    -h|--help)
    sed -n '1,60p' *$0*
    exit 0
    ;;
    *)
    echo *Unknown arg: $1* >&2
    exit 1
    ;;
    esac
done

if [[ ${#**DESTS**[@]} -eq 0 ]]; then
    # Common probes: public DNS, google, and IMDS
    **DESTS**=(*1.1.1.1* *8.8.8.8* ***169**.**254**.**169**.**254***)
fi

have() { command -v *$1* >/dev/null 2>&1; }

hr() { printf '%*s\n' *${**COLUMNS**:-**100**}* '' | tr ' ' '-'; }

headline() {
    hr
    echo *$1*
    hr
}

readlink_base() {
    local p=*$1*
    if [[ -e *$p* ]]; then
    basename *$(readlink -f *$p*)*
    else
    echo *-*
    fi
}

sysval() {
    local f=*$1*
    if [[ -r *$f* ]]; then
    cat *$f*
    else
    echo *-*
    fi
}

# --- system overview ---

headline *System overview* echo *Host: $(hostname)* echo *Kernel: $(uname -r)* echo ***CPU** sockets/**NUMA** (if available):* if have lscpu; then lscpu | egrep -i 'Socket|**NUMA**|Model name|**CPU**\(s\)' || true else echo *  lscpu not found* fi echo

# --- enumerate interfaces ---

headline *Interfaces detected* mapfile -t **IFACES** < <(ls -1 /sys/class/net | grep -vE '^(lo)$' | sort)

if [[ ${#**IFACES**[@]} -eq 0 ]]; then
    echo *No interfaces found (other than lo).*
    exit 0
fi

for IF in *${**IFACES**[@]}*; do echo * - $IF* done echo

# --- per-interface deep mapping ---

for IF in *${**IFACES**[@]}*; do headline *Mapping for interface: $IF*

    echo *[A] Basic link info*
    if have ip; then
    ip -br link show dev *$IF* || true
    ip -br addr show dev *$IF* || true
    else
    echo *ip not found*
    fi
    echo

    echo *[B] sysfs -> **PCI** / driver / **NUMA***
    DEV_PATH=*/sys/class/net/${IF}/device*
    if [[ -e *$DEV_PATH* ]]; then
    PCI_BDF=*$(basename *$(readlink -f *$DEV_PATH*)*)*
    **DRIVER**=*$(readlink_base *$DEV_PATH/driver*)*
    **NUMA**=*$(sysval *$DEV_PATH/numa_node*)*
    **VENDOR**=*$(sysval *$DEV_PATH/vendor*)*
    **DEVICE**=*$(sysval *$DEV_PATH/device*)*

    echo ***PCI** **BDF**:   $PCI_BDF*
    echo *Driver:    $**DRIVER***
    echo ***NUMA** node: $**NUMA***
    echo ***PCI** IDs:   vendor=$**VENDOR** device=$**DEVICE***

    if have lspci; then
    echo
    echo *lspci summary:*
    lspci -s *$PCI_BDF* -nn || true
    else
    echo "lspci not found (install pciutils for richer **PCI** info).*
    fi
    else
    echo *No device backing for $IF (may be virtual/bridge). Skipping **PCI** mapping.*
    continue
    fi
    echo

    echo *[C] RX/TX queues present (sysfs)*
    QUEUE_DIR=*/sys/class/net/${IF}/queues*
    if [[ -d *$QUEUE_DIR* ]]; then
    RXQ_COUNT=*$(ls -1 *$QUEUE_DIR* 2>/dev/null | grep -c '^rx-' || true)*
    TXQ_COUNT=*$(ls -1 *$QUEUE_DIR* 2>/dev/null | grep -c '^tx-' || true)*
    echo *RX queues: $RXQ_COUNT*
    echo *TX queues: $TXQ_COUNT"

    # Show RPS/XPS settings per queue (often useful when debugging skew)
    echo
    echo *Per-queue **RPS**/**XPS** (non-empty masks only):*
    for q in *$QUEUE_DIR*/rx-*; do
    [[ -e *$q* ]] || continue
    qn=*$(basename *$q*)*
    mask=*$(sysval *$q/rps_cpus*)*
    [[ *$mask* != *-* && *$mask* != *0* && *$mask* != *00000000* ]] && echo *  $qn rps_cpus=$mask*
    done
    for q in *$QUEUE_DIR*/tx-*; do
    [[ -e *$q* ]] || continue
    qn=*$(basename *$q*)*
    mask=*$(sysval *$q/xps_cpus*)*
    [[ *$mask* != *-* && *$mask* != *0* && *$mask* != *00000000* ]] && echo *  $qn xps_cpus=$mask*
    done
    else
    echo *No queue directory found.*
    fi
    echo

    echo "[D] **MSI**-X IRQs for this **PCI** device (maps **IRQ** load + **CPU** affinity)*
    MSI_DIR=*/sys/bus/pci/devices/${PCI_BDF}/msi_irqs*
    if [[ -d *$MSI_DIR* ]]; then
    mapfile -t IRQs < <(ls -1 *$MSI_DIR" 2>/dev/null | sort -n || true)
    if [[ ${#IRQs[@]} -eq 0 ]]; then
    echo *No **MSI** IRQs exposed under $MSI_DIR*
    else
    echo "**MSI** IRQs (sorted). **NOTE**: **ENA** typically uses one vector per queue-pair + management.*
    idx=0
    for irq in *${IRQs[@]}"; do
    # /proc/interrupts line
    intr_line=*$(awk -v n=*$irq* '$1 ~ (*^*n*:*) {print; found=1} **END**{if(!found) print **}' /proc/interrupts)*
    aff=*$(sysval */proc/irq/${irq}/smp_affinity_list*)*
    act=*$(sysval */proc/irq/${irq}/actions*)*
    echo "  [vector#${idx}] irq=${irq}  affinity=${aff}  actions=${act}*
    if [[ -n *$intr_line* ]]; then
    echo *    /proc/interrupts: $intr_line"
    fi
    idx=$((idx+1))
    done
    fi
    else
    echo *No **MSI** **IRQ** directory at $MSI_DIR*
    fi
    echo

    echo "[E] **RSS** indirection table -> queue distribution (shows why one queue/**CPU** can run hot)"
    if have ethtool; then
    # Compute histogram of queue indices used in the indirection table.
    # We keep it lightweight by parsing only numbers after *:* lines.
    python3 - <<'PY' *$IF*
import re, subprocess, sys
iface = sys.argv[1]
try:
  out = subprocess.check_output([*ethtool*, *-x*, iface], text=True, stderr=subprocess.**STDOUT**)
except Exception as e:
    print(f*ethtool -x failed: {e}*)
    sys.exit(0)

nums = []
for line in out.splitlines():
    # Lines often look like: *  0:  0  1  2  3 ...*
    m = re.match(r'^\s*\d+\s*:\s*(.*)$', line)
    if not m: 
    continue
    for tok in m.group(1).split():
    if tok.isdigit():
    nums.append(int(tok))

if not nums:
    print("No indirection entries parsed (driver may not expose **RSS** table).")
    sys.exit(0)

from collections import Counter
c = Counter(nums)
total = len(nums)
qs = sorted(c.items())
print(f***RSS** indirection entries: {total}*)
print("Queue -> % of table (bigger % can mean more flows land there):")
for q, cnt in qs:
    pct = (cnt/total)***100**.0
    print(f*  queue {q:>3}: {cnt:>4} entries  ({pct:6.2f}%)*)

# Also show a short excerpt of the raw output header (helps confirm hash func)

print(*\nRaw ethtool -x header (first ~15 lines):*)
for i, line in enumerate(out.splitlines()[:15]):
  print(line)
PY
    else
    echo "ethtool not found (install ethtool to view **RSS**/queue config).*
    fi
    echo

    echo *[F] Optional: quick **NIC** counters (drops/errors/queue stats) via ethtool -S*
    if [[ *$SHOW_STATS" -eq 1 ]]; then
    if have ethtool; then
    # Filter to commonly useful counters without dumping everything.
    ethtool -S *$IF* 2>/dev/null | egrep -i 'drop|err|timeout|reset|rx_queue|tx_queue|miss|buf' || true
    else
    echo *ethtool not found*
    fi
    else
    echo *Skipped (run with --stats to include).*
    fi
    echo

    echo "[G] Routing demonstration: which **NIC** would be used for some destinations?*
    if have ip; then
    for d in *${**DESTS**[@]}*; do
    echo *  ip route get $d:*
    ip route get *$d* 2>/dev/null | sed 's/^/    /' || echo *    (route lookup failed)*
    done
    else
    echo *ip not found*
    fi

echo done

headline *Done* echo *Tip: If one **NIC** is disproportionately busy, compare:* echo * - ip route get <dest> (egress selection)* echo * - **RSS** queue histogram + /proc/interrupts (queue/**IRQ** skew)* echo * - **IRQ** affinity (smp_affinity_list) vs your **CPU** pinning/isolcpus"

What you’ll see (and what it proves)

For each interface (eth0, eth1):

**PCI** **BDF** (e.g. **0000**:00:06.0) and driver (ena)

**NUMA** node for the **PCI** device

Queue counts (rx-* / tx-*)

**MSI** **IRQ** numbers tied to that **PCI** device + current **CPU** affinity

**RSS** indirection distribution showing how the **NIC** maps flows → queues

Route selection showing which **NIC** would be used for given destinations

If you want, I can tailor it to your exact case

If you paste the output for the “busy” **NIC** and the “quiet” **NIC** (just those two sections), I’ll tell you which of these is happening:

routing/policy routing causes skew across ENIs,

**RSS**/elephant-flow causes skew within one **ENI**,

**IRQ** affinity / **NUMA** placement causes skew,

queue count differences across ENIs cause skew.

Also what is the open fabric layer in all this? Thought for 42s

“Open fabric layer” usually refers to OpenFabrics Interfaces (**OFI**) / libfabric (and sometimes the wider OpenFabrics/**RDMA** stack like rdma-core / libibverbs).

The key point: it’s not part of the normal **ENA** (Ethernet) socket path. It’s a different fast-path used mainly for **HPC**/AI on **AWS** via **EFA** (Elastic Fabric Adapter).

Where it sits in the stack Normal **ENA** path (what your **UDP**/**TCP** trading-style apps use)

App → sockets → Linux **TCP**/IP stack → qdisc → **ENA** driver → Nitro card → **VPC** fabric

This uses the kernel network stack, **RSS**, **MSI**-X IRQs, **NAPI**, etc.

OpenFabrics / **OFI** path (what **HPC**/**MPI** apps use with **EFA**)

App/**MPI**/**NCCL** → libfabric (**OFI** **API**) → **EFA** provider → **EFA** device → Nitro / **AWS** fabric

**AWS** explicitly exposes **EFA** through libfabric (**OFI**), and the **EFA** libfabric provider is described as OS bypass / direct hardware access from userspace. Libfabric itself is the user-space **API** implementing **OFI**.

Why it matters for IRQs and “queuing”

With **ENA**, your receive path is fundamentally “interrupts + **NAPI** polling”, and you’ll see lots of activity in /proc/interrupts tied to **ENA** **MSI**-X vectors.

With **OFI**/**EFA**, a lot of the data path is designed for OS-bypass and often uses polling completion queues in user space (i.e., less reliance on the kernel’s per-packet interrupt/**NAPI** model). The control plane still exists, but the data fast path can look very different in perf/interrupt telemetry.

So if someone says “open fabric layer” while you’re debugging **ENA** **IRQ** skew, they may be mixing two worlds:

**ENA** = Ethernet, sockets, kernel networking, **IRQ**/**NAPI**-heavy.

OpenFabrics/**OFI** = high-performance fabric **API**, commonly used with **EFA**, more user-space driven.

Quick way to tell if “OpenFabrics” is actually in use on your box

Do you have an **EFA** device? (often shows up with lsmod | grep efa, and fi_info listing an efa provider, and sometimes **RDMA** devices under /dev/infiniband).

Do your apps use libfabric / **MPI** (OpenMPI/Intel **MPI**), or you see libfabric / rdma-core packages installed?

If you paste:

lsmod | egrep 'ena|efa|ib_'

fi_info -p efa (if installed)

lspci | egrep -i 'Elastic Network|**EFA**|Amazon'

…I’ll tell you whether you’re purely in **ENA**-land or whether **EFA**/**OFI** is actually part of your datapath.

How are the ena devices and how does the numbering work ? Thought for 58s

On **EC2** (including bare metal), each “**ENA** **NIC**” you see in Linux is a PCIe device presented by the Nitro platform, and it corresponds (at the **AWS** control plane level) to an **ENI** attachment.

There are two different “numbering” systems people mix up:

**AWS** attachment ordering (DeviceIndex / NetworkCardIndex)

Linux interface naming (eth0, ens5, enp0s…, eno1, etc.)

1. **AWS** numbering: DeviceIndex and NetworkCardIndex
DeviceIndex (attachment order)

DeviceIndex = 0 is the primary network interface.

Secondary ENIs are typically DeviceIndex = 1, 2, … in the order they’re attached.

NetworkCardIndex (which physical “network card”)

Some instance types have multiple network cards (for very high bandwidth/pps).

NetworkCardIndex = 0 must host the primary interface; additional ENIs can be attached to card index 1..n.

Important: DeviceIndex/NetworkCardIndex are **AWS** concepts. Linux may or may not reflect them directly in interface names.

2. Linux numbering: why you get eth0 vs ens5 (and what the “5” means)
Case A: “Classic” names (eth0, eth1, …)

The kernel assigns eth0, eth1 in probe/discovery order.

That order can change across boots if hardware enumeration timing changes (less stable).

Case B: “Predictable” names (systemd/udev) (ens5, enp0s5, eno1, …)

Modern distros usually enable Predictable Network Interface Names.

The name is derived from hardware topology, commonly the **PCI** location:

en = ethernet

p<bus>s<slot>f<func> pattern (e.g., enp0s5) or the “slot” shorthand you often see on **EC2** like ens5.

So on **EC2**, ens5 usually means “the Ethernet device in **PCI** slot 5” (under that naming scheme). It’s not “**ENI** #5”.

**AWS** even notes you might see eth0 or a predictable name like ens5 depending on OS naming support/config.

3. How **ENI** ↔ Linux interface mapping actually works (the reliable way)

The only reliable mapping is via **MAC** address:

Step 1: Linux view (interface → **MAC**) ip -br link

Step 2: **AWS** metadata view (**MAC** → device-number + **ENI** id)

**IMDS** exposes per-interface details under: /latest/meta-data/network/interfaces/macs/<mac>/... (and includes things like device-number / interface-id).

Example:

**BASE**=[http://**169**.**254**.**169**.**254**/latest/meta-data/network/interfaces/macs](http://**169**.**254**.**169**.**254**/latest/meta-data/network/interfaces/macs)
curl -s $**BASE**/ | tr -d '/' | while read mac; do
    echo ***MAC**=$mac*
    echo -n *  device-number: *; curl -s $**BASE**/$mac/device-number; echo
    echo -n *  interface-id:  *; curl -s $**BASE**/$mac/interface-id; echo
done

That tells you (for each **MAC**):

which **AWS** device-number / attachment index hint it has,

which eni-… it is.

(And from **AWS** **API**/**CLI** you can also see DeviceIndex/NetworkCardIndex for each **ENI** attachment.)

Step 3: Linux view (interface → **PCI** device → **ENA** driver) IF=ens5 readlink -f /sys/class/net/$IF/device      # shows **PCI** **BDF** like **0000**:00:05.0 readlink -f /sys/class/net/$IF/device/driver ethtool -i $IF | egrep 'driver|bus-info'

Now you can say, with evidence: ens5 (**MAC** X) = **ENI** eni-… (DeviceIndex Y) = **PCI** **BDF** … = driver ena

4. Why interface “numbers” can look weird on **AWS**

If you disable predictable naming, you’ll often get eth0, eth1, etc. (but their ordering can be less stable).

If you attach/detach ENIs over time, the **AWS** DeviceIndex can stay consistent, while the Linux name might change (depending on naming policy and enumeration).

On multi-network-card instances, you can have multiple ENIs whose **PCI** topology puts them at different buses/slots, so you might see names that don’t look “sequential” even though DeviceIndex is.

If you paste:

ip -br link

the **IMDS** loop output above

lspci -nn | grep -i ethernet (or just the readlink -f /sys/class/net/*/device lines)

…I can tell you exactly how your box is numbering **ENA** devices (and whether predictable naming or probe order is driving what you see).

give me a diagram showing me how the nics map to the underlying **AWS** hardware/ pci slots and controller and how they're virtualised if indeed they are Thought for 33s

Here’s a conceptual map of what’s going on when you see ena NICs on **EC2** (including bare metal) — from **AWS** “**ENI**” down to PCIe slots/functions, Nitro controller/card, and how it’s virtualised.

Diagram: **ENI** → **ENA** → PCIe → Nitro → **AWS** network
    **AWS** **CONTROL** **PLANE** (**VPC**)
    (**ENI** object: eni-..., SGs, subnets, routing)
    |
    |  attach ENI(s)
    v
+-----------------------------------------------------------+
|                    EC2 INSTANCE (your OS)                 |
|                                                           |
|  Linux netdev: eth0 / ens5 / enp0s6 ...                   |
|    |        MAC: aa:bb:cc:dd:ee:ff                        |
|    |        IP(s): 10.x / 172.x / ...                     |
|    |                                                     |
|    v                                                     |
|  ENA driver (ena.ko)                                     |
|    |  RX/TX rings (per queue)                             |
|    |  MSI-X vector per queue-pair + mgmt vector           |
|    |  NAPI polling under load                             |
|    v                                                     |
|  PCIe function presented to the OS                        |
|    - typically SR-IOV Virtual Function (VF) on most EC2    |
|      (enhanced networking)                                |
|    - looks like a normal PCI device to Linux              |
|                                                           |
|  Example PCI identity in Linux:                            |
|    /sys/class/net/ens5/device  -> 0000:00:05.0            |
+---------------------------|-------------------------------+
    |
    | PCIe link
    v
+-----------------------------------------------------------+
|                   AWS NITRO HARDWARE                      |
|  Nitro Card(s) handle virtualization/offload so host CPU   |
|  isn’t doing most of the network “hypervisor” work         |
|                                                           |
|  - Implements the ENA device model exposed over PCIe       |
|  - DMA to/from instance memory                             |
|  - Enforces isolation / security boundaries                |
+---------------------------|-------------------------------+
    |
    v
    **AWS** **DATACENTER** **NETWORK** **FABRIC**
    (**VPC** dataplane / routing / SGs)

What’s virtualised? On supported instances, “enhanced networking” uses SR-**IOV**, which is a device-virtualization technique where the instance gets a PCIe function that’s backed by **AWS** hardware offload rather than a fully emulated **NIC**. Nitro’s design goal is “bare-metal-like” performance by pushing virtualization functions onto Nitro cards.

Diagram: PCIe slot/function ↔ Linux interface name

This is what you can literally prove on your box:

Linux interface name  ->  sysfs device link       ->  **PCI** **BDF** (bus:dev.func) ens5                  ->  /sys/class/net/ens5/device  ->  **0000**:00:05.0 eth0                  ->  /sys/class/net/eth0/device  ->  **0000**:00:06.0

On many distros, ens5 is “predictable naming” derived from **PCI** location (slot-ish), whereas eth0 is “probe order” naming. (The truth is the **PCI** **BDF** in sysfs, not the string name.)

Diagram: queues ↔ interrupts (why /proc/interrupts has many **ENA** lines)

**ENA** uses multi-queue + **MSI**-X:

**ENA** device (**PCI** function)
    |
    +-- Queue pair 0  -> **MSI**-X **IRQ** N0 -> **CPU** affinity mask -> **NAPI** poll for Q0
    +-- Queue pair 1  -> **MSI**-X **IRQ** N1 -> **CPU** affinity mask -> **NAPI** poll for Q1
    +-- Queue pair 2  -> **MSI**-X **IRQ** N2 -> **CPU** affinity mask -> **NAPI** poll for Q2
    ...
    +-- Management    -> **MSI**-X **IRQ** Nm -> admin/events (**AENQ**/**ACQ**)

The upstream Linux **ENA** docs are explicit: one **MSI**-X vector per queue pair + an additional management vector.

Mermaid version (paste into docs/wiki that renders Mermaid)
flowchart TB
    subgraph **AWS**[***AWS** **VPC** / Control Plane*]
    **ENI**[***ENI** (eni-...)<br/>SGs, subnet, routes*]
    end

    subgraph OS[***EC2** instance (your Linux OS)*]
    **NETDEV**[*Linux netdev<br/>eth0 / ens5<br/>**MAC**, IPs*]
    **ENA**[***ENA** driver (ena.ko)<br/>RX/TX rings + **NAPI***]
    **PCI**[*PCIe function exposed to OS<br/>(often SR-**IOV** VF)*]
    **IRQ**[***MSI**-X IRQs<br/>1 per queue-pair + mgmt*]
    **QUEUES**[*RX/TX queues<br/>**RSS** distributes flows*]
    **NETDEV** --> **ENA** --> **QUEUES**
    **QUEUES** --> **IRQ**
    **PCI** --> **ENA**
    end

    subgraph **NITRO**[*Nitro hardware (cards/controllers)*]
    **NDEV**["Nitro implements **ENA** device model<br/>**DMA** + isolation/offload*]
    end

  **FABRIC**[***AWS** datacenter network fabric<br/>(**VPC** dataplane)"]

    **ENI** --> **NETDEV**
    **PCI** <--> **NDEV**
    **NDEV** --> **FABRIC**

Where “**ENI** numbering” fits in (**AWS** → Linux)

**AWS** instance metadata ties **MAC** → device-number (DeviceIndex hint), which is how you connect “eth0/ens5” back to the **AWS** attachment.

If you want, paste:

ls -l /sys/class/net/*/device

the ena lines from /proc/interrupts

…and I’ll annotate your actual **PCI** BDFs, queue counts, and **IRQ** vectors onto the diagram so it matches your exact host.

how can I confirm we're using sri-ov Thought for 1m 32s

You can confirm SR-**IOV** on **EC2** from two angles:

**AWS**-level truth: “Enhanced networking uses SR-**IOV**” and Nitro instances use **ENA** for enhanced networking.

Host-level evidence: whether the **PCI** device you see in Linux is a Virtual Function (VF) (SR-**IOV**) vs a Physical Function (PF).

Below are practical checks that work well on Nitro + **ENA**.

1. Quick confirmation: are you on the SR-**IOV** enhanced networking path?
- Check the instance attribute (**AWS** **CLI**)

**AWS** explicitly exposes EnaSupport for the instance.

aws ec2 describe-instances --instance-ids i-xxxxxxxx \ --query *Reservations[].Instances[].EnaSupport*

If it returns true, **ENA** is enabled (enhanced networking).

- Check the Linux driver + **PCI** bus-info

**AWS**’ own “test enhanced networking” step is:

ethtool -i eth0

You want to see driver: ena and a **PCI** bus-info like **0000**:00:05.0.

2. “Prove VF vs PF” locally (the most direct SR-**IOV** evidence)

Linux exposes standard sysfs links:

If the device is a VF, it will have a physfn symlink.

If the device is a PF with VFs enabled, it will have virtfn* symlinks.

Single-interface check IF=eth0

**BDF**=*$(ethtool -i *$IF* | awk '/bus-info:/ {print $2}')* echo *IF=$IF  **BDF**=$**BDF***

if [ -L */sys/bus/pci/devices/$**BDF**/physfn* ]; then echo "$IF is a VF (SR-**IOV**) -> physfn: $(readlink -f /sys/bus/pci/devices/$**BDF**/physfn)* else echo *$IF does **NOT** show physfn (could be PF presentation or SR-**IOV** hidden by platform)" fi

# PF-style evidence (only if PF is actually visible to your OS)

ls -l */sys/bus/pci/devices/$**BDF**/virtfn** 2>/dev/null || true

On many **EC2** instances you’ll see VFs (so physfn exists), but you typically won’t see the real PF as a controllable device (**AWS** manages the PF/Nitro side). That’s still consistent with SR-**IOV**.

3. One-shot “report” script for all NICs
#!/usr/bin/env bash
set -euo pipefail

command -v ethtool >/dev/null || { echo *Install ethtool*; exit 1; }

printf *%-10s %-8s %-14s %-5s %-8s %s\n* **IFACE** **DRIVER** **BDF** VF? **NUMA** **EXTRA**
for IF in $(ls /sys/class/net | grep -v '^lo$' | sort); do
    **DRIVER**=*$(ethtool -i *$IF" 2>/dev/null | awk -F': ' '/^driver:/ {print $2}' | head -n1)*
    **BDF**=*$(ethtool -i *$IF* 2>/dev/null | awk -F': ' '/^bus-info:/ {print $2}' | head -n1)*

    VF=*?*
    **NUMA**=*-*
    **EXTRA**=**

    if [[ *$**BDF**" =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9]+$ ]] && [[ -d */sys/bus/pci/devices/$**BDF*** ]]; then
    [[ -r */sys/bus/pci/devices/$**BDF**/numa_node* ]] && **NUMA**=*$(cat /sys/bus/pci/devices/$**BDF**/numa_node)*
    if [[ -L */sys/bus/pci/devices/$**BDF**/physfn* ]]; then
    VF=*VF*
    **EXTRA**=*physfn=$(basename *$(readlink -f */sys/bus/pci/devices/$**BDF**/physfn*)*)*
    else
    VF=*PF?*
    if ls */sys/bus/pci/devices/$**BDF**/virtfn** >/dev/null 2>&1; then
    **EXTRA**=*has-virtfn-links*
    fi
    if [[ -r */sys/bus/pci/devices/$**BDF**/sriov_totalvfs* ]]; then
    **EXTRA**=*${**EXTRA**} sriov_totalvfs=$(cat */sys/bus/pci/devices/$**BDF**/sriov_totalvfs*)*
    fi
    fi
    fi

printf *%-10s %-8s %-14s %-5s %-8s %s\n* *$IF* *${**DRIVER**:-?}* *${**BDF**:-?}* *$VF* *$**NUMA*** *$**EXTRA*** done

How to interpret results on **AWS**

If you see driver: ena (and EnaSupport=true), you’re using enhanced networking.

**AWS** states enhanced networking uses SR-**IOV**.

If sysfs shows physfn, you’ve directly proven the device is a VF, i.e. SR-**IOV**.

If you paste the output of the report script, I’ll tell you whether each **NIC** is presented as a VF, and how that lines up with what you’re seeing in IRQs/queues.

The script produced the following? **IFACE**      **DRIVER**   **BDF**            VF?   **NUMA**     **EXTRA** ens5       ena      **0000**:00:05.0   PF?   -1 ens6       ena      **0000**:00:06.0   PF?   -1 ens7       ena      **0000**:00:07.0   PF?   -1 Thought for 1m 4s

That output is actually expected on a lot of Nitro / bare-metal setups:

You are definitely using **ENA** (driver=ena) and these are real PCIe functions (**0000**:00:05.0, .06.0, .07.0).

The script printed PF? because it didn’t find /sys/bus/pci/devices/<**BDF**>/physfn (the usual “this is a VF” breadcrumb).

**NUMA** -1 just means “kernel doesn’t report a **NUMA** node for this device” (unknown / not exposed), not “wrong”.

Important nuance

**AWS** documents that Enhanced Networking uses SR-**IOV**. But you won’t always be able to see a PF↔VF relationship from inside the instance, because the “real PF” can live on the Nitro side and not be visible/manageable to your OS.

So: “no physfn” does not disprove SR-**IOV** on **EC2**. It only tells you Linux doesn’t see these particular functions as VFs of a visible PF.

How to confirm SR-**IOV** from the instance (best-effort)
1. Confirm “Enhanced networking” is enabled (**AWS** says this is SR-**IOV**)
aws ec2 describe-instances --instance-ids i-**XXXX** \
  --query *Reservations[].Instances[].EnaSupport*

If true, you’re on the enhanced networking path.

2. Check whether the **PCI** function advertises an SR-**IOV** capability (PF indicator)

Run this for each **BDF**:

for bdf in **0000**:00:05.0 **0000**:00:06.0 **0000**:00:07.0; do
    echo *== $bdf ==*
    sudo lspci -vv -s *$bdf* | grep -i -A3 -B2 *SR-**IOV*** || echo *  (no SR-**IOV** capability shown)*
done

If you see an “SR-**IOV**” capability block, that’s strong evidence Linux sees it as a PF that supports VFs (per the kernel **PCI** SR-**IOV** model).

If you don’t, it may be a VF-like presentation or the platform simply doesn’t expose that capability to the guest view.

3. Check sysfs SR-**IOV** knobs (PFs often have these)
for bdf in **0000**:00:05.0 **0000**:00:06.0 **0000**:00:07.0; do
    echo *== $bdf ==*
    for f in sriov_totalvfs sriov_numvfs; do
    if [[ -r /sys/bus/pci/devices/$bdf/$f ]]; then
    echo *  $f=$(cat /sys/bus/pci/devices/$bdf/$f)*
    else
    echo *  $f=not-present*
    fi
    done
done

If sriov_totalvfs exists and is >0, that’s PF-style SR-**IOV** support.

4. Re-check the VF breadcrumb (what my script was looking for)
for bdf in **0000**:00:05.0 **0000**:00:06.0 **0000**:00:07.0; do
    echo *== $bdf ==*
    [[ -L /sys/bus/pci/devices/$bdf/physfn ]] && echo *  VF (physfn exists)* || echo *  not a visible VF*
    ls -1 /sys/bus/pci/devices/$bdf/virtfn* 2>/dev/null | head || true
done

Kernel docs define PF/VF in SR-**IOV** and the sysfs relationships.

What your specific result likely means

Given you see three **ENA** devices at 00:05.0, 00:06.0, 00:07.0 and no physfn, the most likely interpretations are:

You’re on Nitro enhanced networking (SR-**IOV** under the hood), but the PF isn’t exposed to the instance → Linux can’t show physfn.

On bare metal, **AWS** may present PF-like functions to you (still Nitro-backed) without giving you the ability to spawn/manage VFs.

If you paste the output of:

lspci -vv -s **0000**:00:05.0 | sed -n '1,80p'

and whether /sys/bus/pci/devices/**0000**:00:05.0/sriov_totalvfs exists

…I’ll tell you which of the two it is on your host.

so summarise everything above

Here’s the whole story in one place.

What **ENA** NICs are on **AWS** (especially Nitro + bare metal)

The Linux NICs you see (ens5, ens6, ens7) are **ENA** devices presented over PCIe.

They map conceptually like this: Linux netdev (ensX) → **ENA** driver → PCIe function (**0000**:00:05.0 etc.) → Nitro hardware → **AWS** **VPC** fabric

ENIs (**AWS** “network interfaces”) are an **AWS** control-plane object; each attached **ENI** becomes a Linux netdev with its own **MAC**/IPs and its own PCIe-presented **ENA** device.

**IRQ** and queuing model (why you see lots of interrupt lines)

**ENA** is multi-queue.

It uses **MSI**-X interrupts:

typically one **MSI**-X vector per queue-pair (RX+TX) plus a management vector

Linux uses **NAPI**: under load the driver polls in batches to reduce interrupt overhead.

RX flow distribution is usually via **RSS** (hashing 5-tuple) → flows land on a specific RX queue → that queue’s **MSI**-X **IRQ** tends to run on whatever **CPU** its affinity points at.

Why traffic can be “disproportionate” on one **NIC** vs another

Two different kinds of skew:

- Skew across NICs/ENIs (ens5 vs ens6)

Most often because:

Routing / policy routing picks one interface for most destinations (default route, source IP selection, ip rules).

Clients are targeting only one **ENI**/IP (**DNS**/config points there).

**AWS** doesn’t automatically “load-balance” traffic across ENIs like an on-prem **LACP** bond would.

- Skew within one **NIC** (one queue/**CPU** hot)

Most often because:

Elephant flows hash to a single **RSS** queue.

**IRQ** affinity / irqbalance / **CPU** pinning concentrates queues on a subset of CPUs.

**RPS**/**RFS**/**XPS** settings steer work unevenly.

What “open fabric layer” is (and when it matters)

“Open fabric layer” usually means OpenFabrics (**OFI**/libfabric) used with **EFA** for **HPC**/**MPI** style networking.

That’s separate from **ENA** and the normal kernel socket path.

If you’re using **ENA** + **UDP**/**TCP** sockets, OpenFabrics is typically not in the datapath.

How **ENA** device “numbering” works

**AWS** has its own ordering: DeviceIndex (primary **ENI** is 0) and sometimes NetworkCardIndex (on instances with multiple network cards).

Linux names (ens5 / ens6) come from predictable naming based on **PCI** topology (or eth0 probe order if predictable naming is off).

The reliable mapping is: Linux interface ↔ **MAC** ↔ **IMDS** (device-number, eni-id).

Your SR-**IOV** question and your output (PF?)

You got:

ens5 ena **0000**:00:05.0 PF? -1 ens6 ena **0000**:00:06.0 PF? -1 ens7 ena **0000**:00:07.0 PF? -1

That means:

You are definitely using **ENA** and these are real PCIe devices.

The script labelled them PF? only because Linux didn’t show the “VF breadcrumb” (/sys/.../physfn). On **AWS**/Nitro (especially bare metal), it’s common that the PF↔VF relationship isn’t exposed in a way you can see, even though **AWS** enhanced networking is SR-**IOV** under the hood.

**NUMA** -1 just means the kernel isn’t exposing a **NUMA** node for those devices (unknown/not reported), not that something is broken.

The practical confirmation checklist

**ENA** in use: ethtool -i ens5 → driver: ena and a **PCI** bus-info.

What is actually driving skew:

ip route get <dest> (egress interface selection)

/proc/interrupts (which **ENA** vectors are hot)

ethtool -x ens5 (**RSS** indirection distribution)

queue counts via /sys/class/net/ens5/queues and ethtool -l

If you want, paste:

ip route show + ip rule show

the ena lines from /proc/interrupts …and I’ll tell you whether your imbalance is routing/**ENI**-level or **RSS**/**IRQ**/affinity-level, and what to change first.

and give me diagram to explain the relationships

Here are two diagrams that show the relationships end-to-end (**AWS** objects → Linux NICs → PCIe/Nitro → queues/IRQs), plus how skew happens.

Diagram 1: Control plane to hardware dataplane
    **AWS** **CONTROL** **PLANE** (**VPC**)
    ┌─────────────────────────────────────────────┐
    │ **ENI** (eni-...)                           │
    │  - Subnet / SG / routes / IPs / **MAC**     │
    │  - Attachment: DeviceIndex (0,1,2...)       │
    └───────────────────────┬─────────────────────┘
                            │ attach
                            v
┌────────────────────────────────────────────────────────────────────-──┐
│                    **EC2** **INSTANCE** (your Linux OS)               │
│                                                                       │
│  Linux netdev: ens5 / ens6 / ens7                                     │
│   - Name is from predictable naming (**PCI** topology)                │
│   - **MAC**/IP match the **ENI**                                      │
│        │                                                              │
│        v                                                              │
│  **ENA** driver (ena.ko)                                              │
│   - multi-queue RX/TX rings                                           │
│   - **RSS** hashes flows → RX queue                                   │
│        │                                                              │
│        v                                                              │
│  PCIe device/function (what you saw):                                 │
│   ens5 → **0000**:00:05.0    ens6 → **0000**:00:06.0    ens7 → 00:07.0│
└───────────────┬───────────────────────────────────────────────────────┘
                │ PCIe link
                v
┌───────────────────────────────────────────────────────────------------──┐
│                 **AWS** **NITRO** **HARDWARE** (cards/controllers)      │
│  - Implements the **ENA** device model exposed over PCIe                │
│  - Handles offload + isolation + **DMA** to instance memory             │
│  - Backed by **AWS** virtualisation (often SR-**IOV** under the hood)   │
└───────────────┬───────────────────────────────────────────------------──┘
                │
                v
    **AWS** **DATACENTER** **NETWORK** **FABRIC** (**VPC** dataplane)

Diagram 2: Queues, **RSS** and IRQs (where the “hot **CPU** / hot queue” comes from)
                     (for one interface: ens5)
┌───────────────────────────────────────────────────────---------------------------------────┐
│ **ENA** device (**PCI** **0000**:00:05.0)                                                  │
│                                                                                            │ 
│  **RSS** hash (5-tuple etc.)                                                               │
│   ├── Flow A ───────────────┐                                                              │
│   ├── Flow B ───────┐       │                                                              │
│   └── Flow C ───┐   │       │                                                              │ 
│                 v   v       v                                                              │
│        RX queue 0  RX q1   RX q2   ...   RX qN                                             │
│           │         │        │              │                                              │
│           │         │        │              │                                              │
│        **MSI**-X **IRQ**   **MSI**-X **IRQ** **MSI**-X **IRQ**    **MSI**-X **IRQ**        │
│         irq#**100**     irq#**101**   irq#**102**      irq#**10X**                         │
│           │         │        │              │                                              │
│     smp_affinity  smp_aff. smp_aff.     smp_aff.                                           │
│        **CPU** 2        **CPU** 3    **CPU** 10       **CPU** 11                           │
│           │         │        │              │                                              │
│         **NAPI** poll batches packets from that queue                                      │
└──────────────────────────────────────────────────────────---------------------------------─┘

Why skew happens:
- One “elephant” flow can land on one RX queue → one **IRQ**/**CPU** looks hot.
- **IRQ** affinity / irqbalance / pinning can concentrate many queues onto few CPUs.

Diagram 3: Why one **NIC** can be busier than another (**ENI**-level skew)
                   Linux routing / policy routing
┌─────────────────────────────────────────────────────────┐
│ ip route / ip rule decide egress interface per dest     │
└──────────────┬── ───────────────────────────────────────┘
               │
    ┌──────────┴────--------------------------------──────┐
    v                                    v
    ens5 (**ENI** A)           ens6 (**ENI** B)
    default route?         only used for specific subnet?
    source IP chosen?      SG/**NACL** different?
    peers target **ENI** A?    peers never hit **ENI** B?
    │                                                    │
    └──→ Disproportionate traffic on ens5 is expected

If you want, I can turn this into a host-specific diagram by labeling:

each ensX → **PCI** **BDF**,

its queue count,

its **MSI**-X **IRQ** range,

and which CPUs those IRQs are pinned to (from /proc/interrupts + smp_affinity_list).
