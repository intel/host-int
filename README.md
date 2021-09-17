# Host-INT* for packet-telemetry

(* Other names and brands may be claimed as the property of others.)

The full name of this project is "Host-INT for packet-telemetry", but
we will usually refer to it as "Host-INT".

What is Host-INT for packet-telemetry?

* INT is [Inband Network Telemetry](https://p4.org/specs), a public
  specification of header formats and report packet formats for network telemetry, published by the P4.org Applications Working Group.
* A data center operator can run the Host-INT software on any or all
  of the hosts in their network.
  * All endpoints of a flow must be enabled for Host-INT
  * Measures packet loss and one-way packet latency between enabled
    hosts in the network, independently for each application flow.
  * Instruments packets of selected TCP/UDP flows by adding INT
    headers, containing per-flow packet sequence numbers and
    timestamps.
  * By default, telemetry data is collected by systems running Host-INT.
    * Alternately, you may configure Host-INT to send telemetry data
      to an INT collector for network wide analysis, e.g. Intel's
      [Deep Insight Network Analytics
      software](https://www.intel.com/content/www/us/en/products/network-io/programmable-ethernet-switch.html)
* Future releases are planned to enable additional telemetry data
  measurement and collection, assisted by INT-enabled network
  switches, e.g. Intel
  [Tofino](https://www.intel.com/content/www/us/en/products/network-io/programmable-ethernet-switch.html)
  programmable Ethernet switches

This is an Alpha, pre-production project from Intel.  See the
[`LICENSE`](LICENSE) file for information about the license under
which this code is released.


# Documentation

This [slide deck](docs/host-int-project.pptx) gives a technical
overview of the programs involved in the Host-INT project, including
which parts of the software run as user space programs vs. as EBPF
programs loaded into the kernel, and the purpose of each program.

This project uses slight variations of the INT header formats, versus
what is documented in the published specifications.  The primary
reason for these extensions is to include a per-flow packet sequence
number to enable packet loss detection.

This project supports two different encapsulations for adding INT
headers to data packets.

* INT_05_OVER_TCP_UDP
* INT_05_EXTENSION_UDP

For details see [Host_INT_fmt.md](docs/Host_INT_fmt.md).

# Supported systems

This code has been compiled and tested primarily on 2 linux systems.

* Ubuntu 20.04
* Fedora 34

We plan to add support for other Linux distributions in future releases.


# Installation


## Building the project from source code

To obtain a copy of this project:

```bash
git clone https://github.com/intel/host-int
```

To install Ubuntu packages that are needed in order to compile the
code:

```bash
$ ./host-int/scripts/build-setup-ubuntu.sh
$ ./host-int/scripts/install-libbpf.sh
```

To compile this project's code:

```bash
$ cd host-int/src
$ make
```

You can also use the target `make debug` to enable additional trace
logging, intended primarily for developers of this project.


## Installing the compiled binaries system-wide

These commands will install tools under `/sbin` and related service
files under system directories:

```bash
$ cd host-int/src
$ sudo make install
```


# Configuration


## Edit the `hostintd` configuration file

Edit the file `/etc/hostintd.cfg` to specify the network interface
that will receive packets with INT headers, and the node id for this
interface.  This version of the project supports only one network
interface.  The node id should be unique for each host running the
software.

A user can specify other parameters in this configuration file as
well.  Please see the output of `hostintd -h` for the available
parameters.


## Disable NIC offloads that conflict with Host-INT

So far we have tested Host-INT most with all transmit and receive
offloads disabled on the interface where it is enabled, using a
command like the following:

```bash
sudo ethtool -K <interface> rx off tx off
```

Host-INT may also work correctly with fewer of these features
disabled.  This documentation will be updated when this has been
tested to confirm.

## Reduce the TCP MSS

In its initial release, Host-INT adds 36 bytes of INT headers to
selected IPv4+TCP and IPv4+UDP packets.  It cannot add these headers
if this would cause the modified packet to increase in size above the
MTU configured for the outgoing interface.

For TCP, one can ensure that sufficient room is available by
configuring the Maximum Segment Size (MSS) of the output interface to
be small enough.

For INT_05_OVER_TCP_UDP the MSS should be configured to be 76 bytes less
than the MTU of the interface.  This leaves room for 20 bytes for an IPv4
header, plus 20 bytes for a TCP header without options, plus 36 bytes for
the INT header.
For INT_05_EXTENSION_UDP the MSS should be configured to be 76 + 8 bytes
(length of outer udp header) less than the MTU of the interface.

For example, if an interface `en0` on which Host-INT has been
configured has an MTU of 1500 bytes, the following command can be used
to configure its MSS to 1500 - 76 = 1424 bytes:

For INT_05_OVER_TCP_UDP:

```bash
ip route add 10.0.0.1/24 dev en0 advmss 1424
```
For INT_05_EXTENSION_UDP:

```bash
ip route add 10.0.0.1/24 dev en0 advmss 1416
```

# Enabling hosts to receive packets with INT headers

Launching the `hostintd` daemon should be done on all hosts where you
wish to be able to send packets with INT telemetry headers added to
them.  Doing so loads an EBPF program that will remove those INT
headers before the packets are processed by the the Linux kernel
networking code, and for some packets will cause INT report packets to
be generated.


## Launch `hostintd` service

```bash
sudo systemctl start hostintd
```

You can check the status of the `hostintd` service at any time with
the following command.  It is a good idea to do this after the first
time starting the service after you have edited the
`/etc/hostintd.cfg` configuration file, in case you have introduced
any errors.

```bash
sudo systemctl status hostintd -l
```


## Stop hostintd service

```bash
sudo systemctl stop hostintd
```


# Enabling hosts to send packets with INT headers

Do this on a host that you wish to send packets with INT headers, to
enable the Host-INT performance monitoring and debug features for
packets sent from this host to hosts ready to receive them.

```
sudo hostintctl -d <interface> -T source --filename /usr/lib/hostint/intmd_tc_ksource.o --filter-filename <filter_file>
```

where `<interface>` is the network interface that will be enabled to
send out packets with INT headers.

INT headers should only be added to packets destined to hosts that are
prepared to receive them, i.e. on which the `hostintd` service has
been launched earlier.  Each host on which the source program is
running must be configured with an allow list of destination hosts.
The host will only add INT headers to a packet if the destination
address is one in this allow list.

You must create a file containing the allow list, and provide it on
the command line as the `<filter_file>` parameter when enabling a host
to send packets with INT headers This file must contain a list of host
names and/or destination IPv4 addresses, one per line.

For other available parameters, see the output of the command
`hostinctctl -h`.

NOTE: With an empty allow list, Host-INT will not function, because
no packets will have destination addresses matching one in the allow
list.


## Unloading the source program

```
sudo hostintctl -d <interface> -T source -U
```


## Usage Example

Checking packet latency when sending data from the host S interface
`eth1` to the host R interface `eno1`

* On the host S:
 1. Install Host-INT software, following the steps above.
 2. edit `/etc/hostintd.cfg` for INT_05_OVER_TCP_UDP with below content
    ```
    DEV=eth1
    NODEID=2
    OPT=-v 0x04 -m 0x04 -B 5000,10000,20000,40000,60000,120000 -E int_05_over_tcp_udp --filename /usr/lib/hostint/intmd_xdp_ksink.o -o /var/log/hostintd_report.log
    ```

    edit `/etc/hostintd.cfg` for INT_05_EXTENSION_UDP with below content
    ```
    DEV=eth1
    NODEID=2
    OPT=-v 0x04 -m 0x04 -B 5000,10000,20000,40000,60000,120000 -E int_05_extension_udp --filename /usr/lib/hostint/intmd_xdp_uencap_ksink.o -o /var/log/hostintd_report.log
   ```
   NOTE: Same encapsulation must be used on all hosts where Host-INT is
   configured, where those hosts can communicate with each other. Host-INT
   will not work if hosts that communicate with each other use different
   INT encapsulations from each other.
 3. launch hostintd service
    ```
    sudo systemctl start hostintd
    ```
 4. load source EBPF program
    In case of INT_05_OVER_TCP_UDP:
    ```
    sudo hostintctl -d eth1 -T source --filename /usr/lib/hostint/intmd_tc_ksource.o --filter-filename filter.txt
    ```
    In case of INT_05_EXTENSION_UDP:
    ```
    sudo hostintctl -d eth1 -T source --filename /usr/lib/hostint/intmd_tc_uencap_ksource.o --filter-filename filter.txt
    ```
* On the host R:
 1. Install Host-INT software, following the steps above.
 2. edit /etc/hostintd.cfg with below content
    edit `/etc/hostintd.cfg` for INT_05_OVER_TCP_UDP with below content
    ```
    DEV=eno1
    NODEID=3
    OPT=-v 0x04 -m 0x04 -B 5000,10000,20000,40000,60000,120000 -E int_05_over_tcp_udp --filename /usr/lib/hostint/intmd_xdp_ksink.o -o /var/log/hostintd_report.log
    ```
    edit `/etc/hostintd.cfg` for INT_05_EXTENSION_UDP with below content
    ```
    DEV=eno1
    NODEID=3
    OPT=-v 0x04 -m 0x04 -B 5000,10000,20000,40000,60000,120000 -E int_05_extension_udp --filename /usr/lib/hostint/intmd_xdp_uencap_ksink.o -o /var/log/hostintd_report.log
    ```
    NOTE: the host R has NODEID=3, while the host S has NODEID=2
 3. launch hostintd service
    ```
    sudo systemctl start hostintd
    ```
* send a packet from the host S to the host R
* check packet latency
 1. On host R, we see latency record similar to below
    ```
    Seq: 1 Time: 458136 s Type: Latency
      Source  NodeID: 2 IngressPort: 13 EgressPort: 13 IngressTS: 1037040573 ns EgressTS: 1037040573 ns
      Sink    NodeID: 3 IngressPort: 12 EgressPort: 12 IngressTS: 1037050488 ns EgressTS: 1037050488 ns
    ```
 2. Calculate latency

    The packet latency is `1037050488 - 1037040573 = 9915 ns`


# Limitations

* On each system, at most one network interface can be enabled for
  receiving packets with INT headers, or sending packets with INT
  headers.
* Only IPv4+TCP and IPv4+UDP packets are supported for addition of INT
  headers.
* The current implementation uses timestamps from Linux's
  `CLOCK_REALTIME` clock, which is typically synchronized with one or
  more time servers using NTP, the [Network Time
  Protocol](https://en.wikipedia.org/wiki/Network_Time_Protocol).  The
  one-way packet latencies calculated by Host-INT can thus differ
  from the true one-way latency due to inaccuracies of times in the
  source and sink hosts.  When the one-way packet latencies are only a
  few microseconds, as they can often be in a data center, this can
  even lead to negative one-way packet latency measurements, since the
  NTP synchronization inaccuracies are often larger than this.  We are
  considering using a better time synchronization method in the
  future, perhaps one based on the
  [Huygens](https://www.usenix.org/conference/nsdi18/presentation/geng)
  clock synchronization algorithm.


## Limitations specific to UDP packets

* For INT_05_OVER_TCP_UDP, the maximum UDP payload length is the interface
  MTU minus 64 bytes (20-byte IPv4 header + 8-byte UDP header +
  36-byte INT headers = 64 bytes)

* For INT_05_EXTENSION_UDP, the maximum UDP payload length is the interface
  MTU minus 72 bytes (20-byte IPv4 header + 8-byte new UDP header +
  36-byte INT headers + 8-byte original UDP header = 72 bytes)

  * These are the maximum payload lengths for UDP packets for which the
    source host will add INT headers to them. The Host-INT project allows
    applications to send larger UDP payload, too. But INT headers will not
    be added to those packets.

## Limitations specific to TCP packets

* NIC offload features such as
  [TSO](https://en.wikipedia.org/wiki/Large_send_offload)
  must be disabled for Host-INT to correctly add INT headers to
  IPv4+TCP packets sent.
* You must reduce the TCP MSS in order for Host-INT to have room to
  add INT headers to IPv4+TCP packets sent.  If you do not do so, TCP
  packets that are MTU size or slightly smaller will be sent without
  INT headers added.
* This release of Host-INT software reduces the throughput of TCP
  traffic quite significantly, in part because the choices made for
  adding INT headers led us to calculate a full TCP payload checksum
  on every TCP packet sent with INT headers added.  We will find
  improvements for this performance, perhaps by using other choices
  for how INT headers are added to TCP packets.


### TCP superpackets

When Host-INT is configured to add INT headers to packets leaving a
source host, it does so by executing an EBPF program on the Linux
kernel's TC egress hook.  As of the Linux kernel versions we have
tested (primarily 5.8.x through 5.11.x), the Linux kernel will often
call EBPF programs running on this hook with "TCP superpackets",
i.e. packets with Eth+IPv4+TCP+payload where the IPv4 Total Length
field is larger than the configured TCP MSS (Maximum Segment Size).
After the EBPF program is finished processing such a packet, one of
the following happens:

* If NIC TSO (TCP Segmentation Offload) is disabled, the Linux kernel
  networking code will segment this superpacket into multiple
  Eth+IPv4+TCP packets in its GSO (Generic Segmentation Offload) code.
* If NIC TSO offload is enabled, the Linux kernel will send the
  superpacket to the NIC, and the NIC will segment the superpacket
  into multiple Eth+IPv4+TCP packets.

In either case, one or more of the resulting packets sent out of the
source host will not have correct TCP options, and/or not have correct
INT headers.  The sink host has no good way to identify the incorrect
packets, nor to undo the effects.  At the time this fix was made, the
typical sink behavior would be to generate INT reports with incorrect
contents, because the EBPF sink code was misinterpreting part of the
TCP header, options, or original payload as part of an INT header.

To avoid these problems, Host-INT checks for superpackets in the
source EBPF program, i.e. packets such that if we add an INT header to
them, their total size would be over the interface MTU.  The source
EBPF program will not add an INT header to those packets.  Thus none
of the multiple packets that the superpacket is broken up into will
have INT headers, either.

As of version 0.1.0-alpha, this MTU is hard-coded to be 1500 bytes in
the EBPF programs.  We plan to make this configurable in a future
release.

This reduces the usefulness of Host-INT somewhat, since it appears
that such TCP superpackets occur fairly often when the sending TCP
application has a lot of data to send, and the TCP window gets large
enough that sending multiple MTU's worth of data at once would improve
performance.  We do not currently know a way to prevent an EBPF
program running on the TC egress hook in the kernel from being given
TCP superpackets to process.  For example, disabling TSO and GSO in
the source using this command:

```bash
ethtool -K enp0s8 tso off gso off
```

results in a state of the system where TCP superpackets can still
often be given to a TC egress hook EBPF program.

Longer term, there are at least two things that could enable adding
INT headers to each packet after TCP segmentation is complete:

* If NIC TSO offload is disabled, create a new EBPF hook that
  processes packets after the Linux kernel is done with all of its
  processing, before they are sent to the NIC.  One suggestion here
  that seems promising would be to create a new Linux loadable kernel
  module similar to the 8021q driver, which is layered on top of a
  physical Ethernet interface, but has its own MTU that is a
  configurable number of bytes smaller than the MTU of the Ethernet
  interface.  The layered driver would be configurable to process
  packets on a new EBPF hook, and would be allowed to add bytes to the
  packets, in our case INT headers.
* If NIC TSO offload is enabled, use a NIC capable of adding INT
  headers to packets after TCP segmentation offload is performed,
  independently for each segment.


## Limitations regarding IPv4 fragmentation

When an application sends a message to a datagram (i.e. UDP-based)
socket, at least with the Linux kernel versions 5.8.x through 5.11.x
we have tested most with, these packets are fragmented into multiple
IPv4 fragments before the TC egress hook EBPF program runs in the
Host-INT source host.

In general, first fragments, i.e. those with the IPv4 Fragment Offset
field equal to 0, contain the beginning of the original IPv4 payload,
including at least the beginning of the layer 4 header.  Non-first
fragments, i.e. those with the IPv4 Fragment Offset field not equal to
0, never contain a complete layer 4 header, and usually contain no
part of the layer 4 header.

As of version 0.1.0-alpha, Host-INT source and sink EBPF programs
check whether IPv4 packets are non-first fragments, and if so, pass
them through unmodified, i.e. the source host will not add INT headers
to such packets.  The sink EBPF programs never attempt to parse a
layer 4 header in non-first fragments (because there is none to
parse).

Note: If there is ever a scenario where:

* a sending host sends a packet without IP fragmentation, and the
  packet is small enough that the source EBPF program adds an INT
  header to it, and
* later an IP router somewhere between the source and sink hosts
  fragments the packet,

then Host-INT's EBPF program _will not_ attempt to reassemble the IP
fragments and remove the INT header.


# Future work

The functionality described in this document is focused on delivering
Host to Host SLA (service-level agreement) verification capabilities.
While most functionality is common, additional work is required to
support a generic INT-EP implementation with support for all the INT
operational modes INT-MD, INT-MX, INT-XD.
