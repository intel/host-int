# Host-INT* for packet-telemetry

(* Other names and brands may be claimed as the property of others.)

The full name of this project is "Host-INT for packet-telemetry", but
we will usually refer to it as "Host-INT*".

What is Host-INT* for packet-telemetry?

* INT is [Inband Network Telemetry](https://p4.org/specs), a public
  specification of header formats and report packet formats for network telemetry, published by the P4.org Applications Working Group.
* A data center operator can run the Host-INT* software on any or all
  of the hosts in their network.
  * All endpoints of a flow must be enabled for Host-INT* 
  * Measures packet loss and one-way packet latency between enabled
    hosts in the network, independently for each application flow.
  * Instruments packets of selected TCP/UDP flows by adding INT
    headers, containing per-flow packet sequence numbers and
    timestamps.
  * By default, telemetry data is collected by systems running Host-INT*.
    * Alternately, you may configure Host-INT* to send telemetry data
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
overview of the programs involved in the Host-INT* project, including
which parts of the software run as user space programs vs. as EBPF
programs loaded into the kernel, and the purpose of each program.

This project uses slight variations of the INT header formats, versus
what is documented in the published specifications.  The primary
reason for these extensions is to include a per-flow packet sequence
number to enable packet loss detection.  See
[Host_INT_fmt.md](docs/Host_INT_fmt.md) for details of these
header format differences.


# Supported systems

This code has been compiled and tested primarily on Ubuntu 20.04 Linux
systems.  We plan to add support for other Linux distributions in
future releases.


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


## Disable NIC offloads that conflict with Host-INT*

So far we have tested Host-INT* most with all transmit and receive
offloads disabled on the interface where it is enabled, using a
command like the following:

```bash
sudo ethtool -K <interface> rx off tx off
```

Host-INT* may also work correctly with fewer of these features
disabled.  This documentation will be updated when this has been
tested to confirm.


## Reduce the TCP MSS

In its initial release, Host-INT* adds 36 bytes of INT headers to
selected IPv4+TCP and IPv4+UDP packets.  It cannot add these headers
if this would cause the modified packet to increase in size above the
MTU configured for the outgoing interface.

For TCP, one can ensure that sufficient room is available by
configuring the Maximum Segment Size (MSS) of the output interface to
be small enough.

The MSS should be configured to be 76 bytes less than the MTU of the
interface.  This leaves room for 20 bytes for an IPv4 header, plus 20
bytes for a TCP header without options, plus 36 bytes for the INT
header.

For example, if an interface `en0` on which Host-INT* has been
configured has an MTU of 1500 bytes, the following command can be used
to configure its MSS to 1500 - 76 = 1424 bytes:

```bash
ip route add 10.0.0.1/24 dev en0 advmss 1424
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
enable the Host-INT* performance monitoring and debug features for
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

NOTE: With an empty allow list, Host-INT* will not function, because
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
 1. Install Host-INT* software, following the steps above.
 2. edit `/etc/hostintd.cfg` with below content
    ```
    DEV=eth1
    NODEID=2
    OPT=-v 0x04 -m 0x04 --filename /usr/lib/hostint/intmd_xdp_ksink.o -o /var/log/hostintd_report.log
    ```
 3. launch hostintd service
    ```
    sudo systemctl start hostintd
    ```
 4. load source EBPF program
    ```
    sudo hostintctl -d eth1 -T source --filename /usr/lib/hostint/intmd_tc_ksource.o --filter-filename filter.txt
    ```
* On the host R:
 1. Install Host-INT* software, following the steps above.
 2. edit /etc/hostintd.cfg with below content
    ```
    DEV=eno1
    NODEID=3
    OPT=-v 0x04 -m 0x04 --filename /usr/lib/hostint/intmd_xdp_ksink.o -o /var/log/hostintd_report.log
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
* Only IPv4+TCP and IPv4+UDP packets are supported in the first
  release for addition of INT headers.
* The current implementation uses timestamps from Linux's
  `CLOCK_REALTIME` clock, which is typically synchronized with one or
  more time servers using NTP, the [Network Time
  Protocol](https://en.wikipedia.org/wiki/Network_Time_Protocol).  The
  one-way packet latencies calculated by Host-INT* can thus differ
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

* If an application sends a UDP packet such that its payload plus
  IPv4+UDP headers is at most the MTU of the network interface, but
  after adding the 36 bytes of INT headers it would exceed the MTU,
  then the source host will not add INT headers to the packet, and
  thus no INT reports will ever be generated for such packets.  Other
  similar examples that may be less obvious:
  * If an application sends a UDP packet such that its payload plus
    IPv4+UDP headers is larger than the interface MTU, it will be
    fragmented at the IP layer, resulting in two or more IPv4+UDP
    packets.  The conditions above for deciding whether an INT header
    is added to a packet is made independently for each fragment, so
    it is possible that _none_ of the fragments will have an INT
    header, or that only some of them will.


## Limitations specific to TCP packets

Because the TCP-specific limitations of this release of Host-INT*
software are more severe, we consider UDP to be supported, but not
TCP.  Treat the TCP-specific parts of this project as a preview of
what is to come.

* NIC offload features such as
  [TSO](https://en.wikipedia.org/wiki/Large_send_offload)
  must be disabled for Host-INT* to correctly add INT headers to
  IPv4+TCP packets sent.
* You must reduce the TCP MSS in order for Host-INT* to have room to
  add INT headers to IPv4+TCP packets sent.  If you do not do so, TCP
  packets that are MTU size or slightly smaller will be sent without
  INT headers added.
* There is a known issue where the contents of INT reports generated
  due to TCP packets can be filled in with incorrect values.
* This release of Host-INT* software reduces the throughput of TCP
  traffic quite significantly, in part because the choices made for
  adding INT headers led us to calculate a full TCP payload checksum
  on every TCP packet sent with INT headers added.  We will find
  improvements for this performance, perhaps by using other choices
  for how INT headers are added to TCP packets.


# Future work

The functionality described in this document is focused on delivering
Host to Host SLA (service-level agreement) verification capabilities.
While most functionality is common, additional work is required to
support a generic INT-EP implementation with support for all the INT
operational modes INT-MD, INT-MX, INT-XD.
