# Host INT extensions to INT version 0.5 specifications

The sequence number extension requires the inclusion of both the
hop-by-hop header and the equivalent of a destination header.  The
hop-by-hop header provides the telemetry data of the source and sink
hops, while the equivalent of a destination header provides the
sequence number information for the flow.  The sequence number is a
flow specific, per packet monotonically increasing value. We define a
new Type code to describe this format of hop-by-hop header that
includes a sequence number.

Host INT currently only supports adding INT headers to IPv4 packets.
The INT native shim header is utilized. The Host-INT project supports
two different encapsulations for adding INT headers to data packets.

INT_05_OVER_TCP_UDP:

INT_05_OVER_TCP_UDP uses the option of modifying the DSCP field inside of the IPv4
header's Type of Service field to distinguish between packets with INT
headers versus those without, with the assumption that network
administrators will dedicate one or more DSCP values for this purpose
in their network.

INT_05_EXTENSION_UDP:

INT_05_EXTENSION_UDP adds a UDP header with a specified destination port
following the IP header. The original IP payload remains unchanged from
the original packet, after the new UDP header followed by the INT headers.
When using the INT_05_EXTENSION_UDP encapsulation, packets with INT headers
are identified by using a configured UDP destination port value, 33122 by
default. The IPv4 header's protocol value is replaced with 17 at the source
to indicate that a UDP header follows. The original packet's protocol value
is copied to a field in the INT tail header, and the Host-INT EBPF program
in the sink host uses this to restore the IPv4 protocol field to its
original value before passing the packet to the sink host's Linux kernel.

## Description of individual INT headers

The 4-byte INT native shim is placed after the L4 headers:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Type      |   Reserved    |    Length     |   Reserved  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[The figure above corresponds to `struct int_shim_hdr` in Host INT
code.]

**Type:** New type ID for parsing format specific to Host INT, Type
  **3**.  This type indicates that a sequence number for the flow
  follows the INT stack.  The sequence number is a 4-byte field, and
  the sequence number plus an INT tail header are both counted in the
  Length field.

**Length:** Total length of INT headers including this shim and
  metadata stacks, in units of 4-byte words.

**Sequence Number:** The INT metadata stack is followed by a 4-byte
  flow sequence number.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Sequence Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[There is no `struct` defined in Host INT to hold the sequence
number.]

**INT Tail Header:** The sequence number is followed by a 4-byte int
tail header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Proto      |     Destination port          | Reserved      |
|0 0 0 0 0 0 0 0|0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0|0 0 0 0 0 0 0 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[The figure above corresponds to `struct int_tail_hdr` in Host INT
code.]

The INT stack is a single hop stack.  It is used so that we may
calculate one-way packet latencies between hosts:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Ver |Rep|C|E|R R R| Ins Cnt |  Max Hop Cnt  | Total Hop Cnt |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Instruction Bitmap       |           Reserved          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    INT Metadata Stack (varying number of fixed-size values)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               . . .                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Last INT metadata                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[In the figure above, the first 8 bytes corresponds to `struct
int_metadata_hdr` in Host INT code.]


## Combined INT header sequence sent in packets from source hosts

The figure below shows the complete sequence of INT headers added by a
source host.  If the original packet is IPv4+UDP, these INT headers
are added immediately after the UDP header.  If the original packet is
IPv4+TCP, these INT headers are added immediately after the first 20
bytes of the TCP header, before any TCP options.

In the Host INT software, the source and sink hosts record their time
in the ingress timestamp field of its metadata, in units of
nanoseconds.

In both the source and sink hosts, the egress timestamp field is
always identical to the ingress timestamp field, and the egress port
field is always identical to the ingress port field.

The INT instruction bits contain 1 for both ingress and egress
timestamps.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Type     |   Reserved    |    Length     |    Reserved   |
|0 0 0 0 0 0 1 1|x x x x x x x x|0 0 0 0 1 0 0 1|x x x x x x x x|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  |Rep|C|E|R R R| Ins Cnt |  Max Hop Cnt  | Total Hop Cnt |
|0 0 0 0|0 0|0|0|x x x|0 0 1 0 0|0 0 0 0 0 0 1 0|0 0 0 0 0 0 0 1|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Instruction Bitmap     |            Reserved           |
|1 1 0 0 1 1 0 0 0 0 0 0 0 0 0 0|x x x x x x x x x x x x x x x x|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  +-+
|                         source node ID                        |    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    s
|       source ingress port     |  source egress port: NA       |    r
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    c
|                         ingress timestamp                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    M
|                          egress timestamp: NA                 |    D
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  +-+
|                         Sequence Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Proto      |     Destination port          | Reserved      |
|0 0 0 0 0 0 0 0|0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0|0 0 0 0 0 0 0 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[The first 4 bytes in the figure above corresponds to `struct
int_shim_hdr`.  The next 8 bytes corresponds to `struct
int_metadata_hdr`, and the next 16 bytes to `struct
int_metadata_entry` inserted by the source host.  There is no struct
defined to hold the sequence number field.  The last 4 bytes
corresponds to `struct int_tail_hdr`.]

**Ver:** Host INT uses version 0, since it does not change any
  semantics of this header.

**Rep:** 0

**C & E:** 0

**Instruction Count:** 4

**Max Hop Count:** 2.  It would be reasonable to increase this value
  if there were network devices that added their own metadata, but for
  the current Host INT software we have tested scenarios where only
  the source and sink hosts add data to the INT header.

**Total Hop Count:** 1 as it leaves the source host.

**Instruction bitmap:** 0xCC00


## Combined INT header sequence in packets processed by sink hosts

The sink generates INT reports only for selected packets, e.g. the
first packet of a flow, or if the one-way latency changes
significantly between consecutive packets in the same flow.

If the sink generates an INT report, then the sink must behave as if
these steps occurred, in this order:

* The sink adds its metadata to the received packet's INT header,
  increasing the Length and Total Hop Count fields appropriately.
* Generate the INT report based upon the packet's new modified INT
  header.

The Host INT implementation behaves this way, but in order to simplify
the sink EBPF code, a user space program on the sink does the actual
insertion of the sink's metadata into the proper position within the
INT header.

The final INT header stack looks as follows after the sink has added
its metadata.  Note that the sink host removes the 4-byte INT tail
header after the Sequence Number.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Type     |   Reserved    |    Length     |    Reserved   |
|0 0 0 0 0 0 1 1|x x x x x x x x|0 0 0 0 1 1 0 0|x x x x x x x x|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  |Rep|C|E|R R R| Ins Cnt |  Max Hop Cnt  | Total Hop Cnt |
h0 0 0 0|0 0|0|0|x x x|0 0 1 0 0|0 0 0 0 0 0 1 0|0 0 0 0 0 0 1 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Instruction Bitmap     |            Reserved           |
|1 1 0 0 1 1 0 0 0 0 0 0 0 0 0 0|x x x x x x x x x x x x x x x x|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  +-+
|                          sink node ID                         |    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    s
|    sink ingress port: NA      |        sink egress port       |    i
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    n
|                         ingress timestamp: NA                 |    k
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    M
|                          egress timestamp                     |    D
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  +-+
|                         source node ID                        |    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    s
|       source ingress port     |  source egress port: NA       |    r
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    c
|                         ingress timestamp                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    M
|                          egress timestamp: NA                 |    D
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  +-+
|                         Sequence Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[The first 4 bytes in the figure above corresponds to `struct
int_shim_hdr`.  The next 8 bytes corresponds to `struct
int_metadata_hdr`.  The next 16 bytes to `struct int_metadata_entry`
inserted by the sink host, and the 16 bytes after that to `struct
int_metadata_entry` inserted by the source host.  There is no struct
defined to hold the sequence number.]

**Total Hop Count:** 2


# Report Formats

INT report packets are sent as UDP datagrams.  The destination UDP
port can be configured by those installing Host INT using the
`--server-port` command line option to `hostintd` or `hostintctl`.  If
not specified, the default destination UDP port for INT report packets
is 32766.  Host INT uses two types of report formats: INT/IPv4 and
Drop-Summary reports.


## Report Common Header

The following header appears at the beginning of the UDP payload of
all INT report packets.

It is identical to the header in Section 3.2.1 "Telemetry Report Fixed
Header (12 octets)" of [TR05].

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  |NProto |D|Q|F|          Reserved           |   hw_id   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Report Sequence Number                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Report Timestamp                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[The figure above corresponds to `struct int_report_hdr` in Host INT
code.]


## INT/IPv4 Report

An INT/IPv4 report begins with a report common header with the
`NProto` field equal to 4, indicating that the first header after the
report common header is IPv4, not Ethernet.

After the report common header is the beginning of the data packet
that caused the report to be generated, starting with its IPv4 header.
The portion of the data packet that is included in the report is at
least until the end of all INT headers in the packet.  The INT headers
included will be as updated in a sink host, as described in [this
section](#Combined-INT-header-sequence-in-packets-processed-by-sink-hosts).

In these reports, the **F** field is 1.

The full INT report packet thus consists of:

+ IP + UDP header with destination port for the INT collector process,
  as described in [this section](#report-formats).
+ A report common header as described in [this
  section](#report-common-header).
+ The original data packet's IPv4 + TCP/UDP + INT Headers, with INT
  headers as described in [this
  section](#Combined-INT-header-sequence-in-packets-processed-by-sink-hosts).
  If the packet is TCP, only the first 20 bytes of the TCP header will
  be included in the report.

This is equivalent to the original INT/Ethernet report, except we do
not include the Ethernet header.  Including the Ethernet header is
easier for some switch ASIC implementations of INT, but they are not
strictly necessary for the INT report collector, and in the Host INT
implementation we can optimize the report by omitting the Ethernet
header.


## Drop-Summary Report

We have created a new Drop-Summary report, to report packet loss to
the INT report collector.  The report consists of the common report
header with the **D** field 1 and **NProto** 3, followed by the
following metadata:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           source node ID                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            sink node ID                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    ingress port: source       |        egress port: sink      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            gap timestamp                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        gap sequence number                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             gap count                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[The figure above corresponds to `struct int_drop_summary_data` in
Host INT code.]

**source node Id:** Id of ingress node of reported flow.

**sink node Id:** Id of the egress node that detected and reported the
  drops.

**ingress port:** ingress port Id from source INT hop metadata.

**egress port:** egress port Id from sink INT hop metadata.

**gap timestamp:** timestamp at which flow-seq-no "gap" first
  detected.

**gap sequence number:** flow sequence number of start of the gap.

**gap count:** number packets inferred as dropped in this gap.

The sending of INT drop reports is triggered by a periodic sweep of
the per-flow data maintained by each sink host, not by the arrival of
a data packet for the flow.  After the drop-summary report header
above, Host-INT appends a synthesized IPv4 header, and a synthesized
TCP or UDP header.  All fields in these two headers will be 0 except
for the following:

+ IPv4 version is 4
+ IPv4 IHL is 5
+ IPv4 protocol is the correct value for TCP or UDP
+ IPv4 source and destination address are correct for the flow
+ TCP/UDP source and destination ports are correct for the flow


# References

[INT05] "In-band Network Telemetry (INT)", v0.5, The P4.org
Applications Working Group, 2017-Dec-11,
https://github.com/p4lang/p4-applications/blob/master/docs/INT_v0_5.pdf

[TR05] "Telemetry Report Format Specification", v0.5, The P4.org
Applications Working Group, 2017-Nov-10,
https://github.com/p4lang/p4-applications/blob/master/docs/telemetry_report_v0_5.pdf
