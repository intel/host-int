# Known issues in version 1.0.0


## May add INT encapsulation to INT report packets, causing too many reports

If you use the `--sender-collector-port` option to enable a host
sending INT reports back to the source IPv4 address of data packets,
the INT report packets themselves can have INT headers added to them,
resulting in multiple INT report packets between the pair of hosts for
each INT report that was triggered by a normal data packet (i.e. not
an INT report packet).

For now, you can avoid this issue by not using the
`--sender-collector-port` option.  We plan to address this in a future
release by disabling the adding of INT headers to INT report packets.
(MID-199)


## High rate of INT reports can cause reports to be lost

There may be scenarios where INT report packets are generated towards
an INT collector faster than is reasonable for it to keep up,
resulting in some INT reports being dropped.  The rate of INT reports
for reasons of latency changes can be reduced by changing the latency
bucket configuration (using the `-B` command line option). (MID-187,
MID-200)


## Data race in updating EBPF maps can cause over-reporting of packet drops

There is a data race between the sink EBPF program updating per-flow
statistics counting dropped packets in the flow statistics EBPF map,
and the way the `hostintd` user space program reads and then later
writes back entries in that map.  This can result in INT reports with
larger numbers of dropped packets than actually were
detected. (MID-153)


## `hostintd` stops printing to log file if it is deleted then recreated

(MID-140)


## No detection of useless DSCP configuration values

The `hostintd` program allows configuration of DSCP values and masks
where Host-INT does not function properly with the
`INT_05_OVER_TCP_UDP` encapsulation, e.g. mask and value both 0.  This
can easily be avoided by providing useful configuration values, such
as the ones in the configuration exmaples of the
documentation. (MID-136)


## No detection of duplicate Node IDs

Host-INT makes no checks to detect if a user has configured more
than one host with the same Node ID value. (MID-135)
