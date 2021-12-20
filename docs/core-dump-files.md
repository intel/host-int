# Enabling generation of core dump files for Host-INT

These are some hopefully brief notes on enabling core dumps for
Host-INT user space processes such as hostintd and hostintcol, and
where to find them if one of these processes crashes in a way that
produces a core dump file.


# The `core_pattern` kernel configuration file

The location where core dump files are written is determined by kernel
configuration.  The first place to check is in the contents of this
file:

```
cat /proc/sys/kernel/core_pattern
```

On an Ubuntu 20.04 Desktop Linux system with no customizations, the
contents of this file are:

```
|/usr/share/apport/apport %p %s %c %d %P %E
```

See [this section](#ubuntu-systems-with-apport) for more details about
such systems.

On another Ubuntu 20.04 system we have seen this in the `core_pattern`
file:

```
|/lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h
```

and a similar one appears on a default Fedora 34 workstation system:

```
|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h
```

See [this
section](#ubuntu-and-fedora-systems-with-systemd-coredump-configured)
for more details about such systems.


## Ubuntu systems with Apport

That indicates that this system is configured to use Apport for
recording information about crashing processes.  For more information
on Apport, these articles may be helpful:

+ https://askubuntu.com/questions/966407/where-do-i-find-the-core-dump-in-ubuntu-16-04lts
+ https://wiki.ubuntu.com/Apport

In our testing on such a system, running this command enabled Apport
for writing crash files into the `/var/crash` directory:

```bash
sudo systemctl enable apport.service
```

After doing that, you can start the `hostintd` process, then send it
an abort signal (signal 6) that should cause it to write a core file:

```bash
sudo systemctl start hostintd
sudo systemctl status hostintd --no-pager
```

Find the numeric process ID of hostintd after the "Main PID" label of
the output, e.g. 5785 in the example command below for sending that
process signal 6:

```bash
sudo kill -6 5785
```

This caused a text-only file (not a binary core dump file) to be
written in the `/var/crash` directory, e.g.:

```bash
$ ls -l /var/crash
total 268
-rw-r----- 1 root whoopsie 160465 Nov  4 14:20 _usr_sbin_hostintd.0.crash
-rw-r--r-- 1 root whoopsie      0 Nov  4 14:20 _usr_sbin_hostintd.0.upload
```

The binary core dump file is encoded in an ASCII format inside of the
file `_usr_sbin_hostintd.0.crash`.  It can be extracted using a
command like this:

```bash
$ sudo apport-unpack /var/crash/_usr_sbin_hostintd.0.crash crash1

$ ls crash1
ApportVersion	      DistroRelease	   ProblemType	       ProcStatus		   StacktraceTop
Architecture	      ExecutablePath	   ProcCmdline	       ProcVersionSignature	   Tags
CasperMD5CheckResult  ExecutableTimestamp  ProcCpuinfoMinimal  Registers		   ThreadStacktrace
CoreDump	      InstallationDate	   ProcCwd	       Signal			   Uname
Date		      InstallationMedia    ProcEnviron	       Stacktrace		   UpgradeStatus
Disassembly	      JournalErrors	   ProcMaps	       StacktraceAddressSignature  UserGroups

$ file crash1/CoreDump 
crash1/CoreDump: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from '/sbin/hostintd -d v4 -n 2 -v 0x04 -m 0x04 -B 50000000,100000000,225000000,50000', real uid: 0, effective uid: 0, real gid: 0, effective gid: 0, execfn: '/sbin/hostintd', platform: 'x86_64'

$ gdb /usr/sbin/hostintd crash1/CoreDump 
```

If the `gdb` command above succeeds in starting, you can then use the
`bt` command to get a stack backtrace of program when it crashed, and
any other `gdb` commands that may help track down the root cause of
the crash.


## Ubuntu and Fedora systems with `systemd-coredump` configured

This section should be relevant to you if you see output of this
command that mentions `systemd-coredump`:

```
$ cat /proc/sys/kernel/core_pattern
|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h
```

You can use the `coredumpctl list` command to see if there are any
core dump files that have been created and saved on the system:

```bash
$ coredumpctl list
TIME                          PID UID GID SIG     COREFILE     EXE                SIZE
Fri 2021-11-05 16:34:52 EDT 41865   0   0 SIGABRT inaccessible /usr/sbin/hostintd  n/a
```

The `coredumpctl dump` command can be used to create a core dump file
in a directory and file name that you specify.  In the example command
below, I show selecting which core dump from the output above using
the PID value.  Check the `coredumpctl` manual page for other ways of
selecting a core dump file.

```bash
$ sudo coredumpctl dump --output=pid-41865.core 41865

$ file pid-41865.core
pid-41865.core: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from '/sbin/hostintd -d v4 -n 2 -v 0x04 -m 0x04 -B 50000000,100000000,225000000,50000', real uid: 0, effective uid: 0, real gid: 0, effective gid: 0, execfn: '/sbin/hostintd', platform: 'x86_64'

$ gdb /usr/sbin/hostintd pid-41865.core
```
