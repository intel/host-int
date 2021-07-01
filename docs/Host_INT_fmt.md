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
The INT native shim header is utilized.  Host INT uses the option of
modifying the DSCP field inside of the IPv4 header's Type of Service
field to distinguish between packets with INT headers versus those
without, with the assumption that network administrators will dedicate
one or more DSCP values for this purpose in their network.

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
  **3**.  This type will indicate that a sequence number for the flow,
  and 4 reserved bytes, follow the INT stack.  The sequence number
  will also be a 4-byte field, and the sequence number plus 4 reserved
  bytes are both counted in the Length field.

**Length:** Total length of INT headers including this shim and
  metadata stacks, in units of 4-byte words.

**Sequence Number:** The INT metadata stack will be followed by a
  4-byte flow sequence number, and 4 reserved bytes:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Sequence Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Reserved                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[There is no `struct` defined in Host INT to hold the sequence number
or reserved field.]

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

In the Host INT software, the source host records its time in both the
ingress and egress timestamp fields of its metadata.  The sink host
records its time in both the ingress and egress timestamp of its
metadata.  The INT instruction bits contain 1 for both ingress and
egress timestamp instructions.

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
|                            Reserved                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[The first 4 bytes in the figure above corresponds to `struct
int_shim_hdr`.  The next 8 bytes corresponds to `struct
int_metadata_hdr`, and the next 16 bytes to `struct
int_metadata_entry` inserted by the source host.  There is no struct
defined to hold the sequence number or reserved fields.]

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
its metadata.  Note that the sink host also removes the 4-byte
reserved field after the Sequence Number:

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


## Report Format

INT report packets are sent as UDP datagrams.  The destination UDP
port can be configured by those installing Host INT.  Host INT uses
two types of report formats: INT/IPv4 and Drop-Summary reports.


### Report Common Header

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


### INT/IPv4 Report

The INT/IPv4 report consists of the report common header, with the
next protocol as IPv4.  It includes the IPv4 and protocol headers with
enough information to identify the flow, followed by the INT header
stack.  This is equivalent to the original INT/Ethernet report except
we are not including the Ethernet headers.  Including the Ethernet
headers is easier for some switch ASIC implementations of INT, but
they are not strictly necesary for the INT report collector, and in
the Host INT implementation we can optimize the report by omitting the
Ethernet header.

In these reports, the **F** field is 1 and **NProto** is 4.


### Drop-Summary Report

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

The packet's original L3 and L4 headers are appended to the report,
immediately after the header above.
