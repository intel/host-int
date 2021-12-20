# Changes to Host-INT for Packet Telemetry in version 1.0.0


## New features

* Add packet count statistics to source and sink EBPF programs that
  count different types of packets that have been processed, and each
  possible error condition that can be encountered.

* Add several command line options to `hostintctl` to show useful
  information:
  * `--show-statistics` shows packet counts statistics maintained by
    source and sink EBPF programs.
  * `--show-config-map` shows the current configuration values used by
    the source and sink EBPF programs.
  * `--show-filter-entries` shows the currently configured filter
    entries, i.e. destination IP addresses that, when a packet is
    destined to one of those IP addresses, a host should add INT
    headers to the packet.
  * `--show-latency-bucket` shows the configured ranges of one-way
    packet latencies such that, when a packet's latency falls into a
    different range than the previous packet, a latency INT report is
    immediately triggered.

* Changed default timeout to delete idle flows from 2 seconds to 2
  minutes.

* Changed configuration value of DSCP to only modify 6-bit DSCP
  portion of the IPv4 ToS byte, not the entire 8-bit field.

* Change `hostintctl` so that when attempting to load a source EBPF
  program, it prevents doing so if the `hostintd` service is not
  running.  Automatically use the same node ID for the source EBPF
  program as configured for the sink.

* Update libbpf to version 0.3


## Fixes

* Improved checking of input values from configuration file and from
  command line options, with explicit error messages when one is out
  of range, and return non-0 exit status.

* Improved error checking throughout, and return non-0 exit status
  when errors occur.

* Consistently use variables of the correct size when reading and
  writing the configuration EBPF maps.

* Use `sigaction(2)` instead of deprecated `signal(2)` system calls.

* Add mutex locks to protect access to a handful of global variables
  in `hostintd`, which is a multi-threaded program.  Also add locking
  to ensure that calls to logging functions are done one thread at a
  time.

* Fixed issues found by static analysis.


## Documentation

* Added documentation with example configuration of `logrotate` Linux
  utility for configuring log rotation.

* Add instructions on finding hostintd core dump files on supported
  Linux distributions.


# Changes to Host-INT for Packet Telemetry in version 0.1.1-alpha

## New features

* Change the format of latency INT reports to add the node ID of the
  sink host generating the report after the Telemetry Report Fixed
  Header, before the IP header of the packet that caused the latency
  INT report to be generated.  This can make it easier for the
  receiver of the INT reports to determine the source of the report,
  even when there are NAT devices that may have modified the IP and/or
  UDP header of the report packet between the host sending the report
  and the report collector.  The old latency INT report format can
  still be enabled with the new `--no-sw-id-after-report-hdr` command
  line option to `hostintd`.

* Start `hostintd` enabled to write core dump files if it crashes.


## Fixes

* Fix a multi-threading bug in `hostintd` where it could crash if one
  thread was attempting to send a latency report while another was
  attempting to send a drop report.

* Additional multi-threaded safety improvements.

* Replace all calls to the obsolete `gethostbyname(3)` with
  `getaddrinfo(3)`.

* Fixed issues found by static analysis.


# Changes to Host-INT for Packet Telemetry in version 0.1.0-alpha

## New features

* Add EBPF programs for a new UDP-based INT data packet encapsulation.
  See mentions of INT_05_EXTENSION_UDP in the documentation.  The
  original INT encapsulation in the first release has been named
  INT_05_OVER_TCP_UDP.

* Add new command line option `-V` / `--Version` to user space
  programs to show the version of Host-INT that is installed.

* Cause the sink host to generate a latency report for a flow not only
  if the latency changed significantly since the last packet was
  received, but also if no latency report has been generated for the
  flow in the last 2 seconds.  That default time can be configured.

* Add the packet 5-tuple, i.e. IP source and destination address,
  protocol, and layer 4 source and destination port, to the INT report
  log files, both the one written by `hostintd`, and the one written
  by `hostintcol`.

* Allow the one-way latency bucket interval end points to be
  configured by the user.  Formerly these intervals were hard-coded in
  the EBPF source code to be 50, 100, 225, 500, and 750 milliseconds.
  Those values were chosen for a wide-area network deployment, but are
  too long to be useful for typical data center networks.  See the new
  '-B' command line option of `hostintd`.

* Changes to enable the project to compile and run on Fedora 34 Linux.
  See new scripts `build-setup-fedora.sh` and `test-setup-fedora.sh`
  in the `scripts` directory.


## Fixes

* No longer attempt to add INT headers to TCP superpackets.  See [TCP
  superpackets](README.md#tcp-superpackets) in the project README for
  more details.

* Improve handling of IPv4 non-first fragment packets.  See
  [Limitations regarding IPv4
  fragmentation](README.md#limitations-regarding-ipv4-fragmentation)
  in the project README for more details.

* Correct some arithmetic in the code for handling periodic scheduling
  of events in the Host-INT user space programs, which prevented them
  from performing periodic tasks such as updating the time offset EBPF
  map entry correctly.

* Fixes to maintaining and reporting drop statistics
  * Corrections to the EBPF sink in its maintaining packet drop
    statistics.
  * Reduce the likelihood of data races between the EBPF sink program
    updating drop statistics, and `hostintd` reading the drop
    statistics.  There is still a possibility of a data race that we
    plan to fix more fully in the future, but the most common error
    seen before, where `hostintd` generated INT drop reports with
    packet drop counts that were clearly too large, should be
    eliminated with this fix.

* The user space programs could incorrectly delete EBPF map entries
  tracking statistics for flows with active packet traffic, mistakenly
  treating them as if no packet had arrived for a long time.
  Corrected the handling of time stamps in user space programs so this
  no longer happens.

* Change `hostintcol` so that it can process received INT report
  packets as fast as possible.  Formerly it was limited to processing
  received INT report packets at most once every 10 milliseconds.

* Fixed a multi-thread data race bug in the handling of sequence
  numbers placed into INT report packets sent by `hostintd`.

* Fixed issues found by static analysis.
