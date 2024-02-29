# bincapz

![bincapz logo](./images/logo_small.jpg)

Enumerate the capabilities of a binary through static artifact analysis.

## Features

- Excellent support for Linux (ELF) and macOS (Mach-O) binaries
- Also supports binaries for other POSIX platforms (OpenBSD, FreeBSD, etc)
- Works for analyzing code written in C, ObjC, Swift, Go, PHP, Python, Perl, and more.
- Enumerates syscalls, pledge(2) classes, and Linux capability(7) requirements
- Integrated Malware detection (10,000+ rules)
- Supports [YARA forge](https://yarahq.github.io/), which integrates rules from Avast, Elastic, FireEye, Google, Mandiant, Nextron, ReversingLabs and more.
- Generic support for any architecture (arm64, amd64, riscv, ppc)
- Diff-friendly output (JSON, table, simple) to detect when capabilities change
- CI/CD friendly
  
## Shortcomings

- Does not extract archive files of any sort (jar, zip, apk)
- Does not understand Java bytecode
- It's slow! (~5 seconds per binary)

## Installation

```shell
go install github.com/chainguard-dev/bincapz@latest
```

## Demo - ping

When run against /sbin/ping:

```
+-------+----------------------------+--------------------------+------------------------------------------------------------+
| RISK  |            KEY             |          VALUES          |                        DESCRIPTION                         |
+-------+----------------------------+--------------------------+------------------------------------------------------------+
| 1/LOW | fs/device/control          | ioctl                    | manipulate the device parameters of special files          |
| 1/LOW | net/icmp                   | ICMP                     | ICMP (Internet Control Message Protocol), aka ping packets |
| 1/LOW | net/interface/get          | if_nametoindex           | libc functions for retrieving network interface            |
| 1/LOW | net/interface/list         | freeifaddrs getifaddrs   | list network interfaces and their associated addresses     |
| 1/LOW | net/ip/multicast/send      | multicast                | Send data to multiple nodes simultaneously                 |
| 1/LOW | net/ip/send/unicast        | unicast                  | send data to the internet                                  |
| 1/LOW | net/socket/local/address   | getsockname              | get local address of connected socket                      |
| 1/LOW | net/socket/receive         | recvmsg                  | receive a message from a socket                            |
| 1/LOW | net/socket/send            | sendmsg sendto           | send a message to a socket                                 |
| 1/LOW | process/current/userid/set | setuid                   | set real and effective user ID of process                  |
| 1/LOW | ref/path/usr               | /usr/share/locale        | References paths within /usr/                              |
| 2/MED | net/hostport/parse         | freeaddrinfo getaddrinfo | Network address and service translation                    |
| 2/MED | net/ip/parse               | inet_pton                | Parse an IP address (IPv4 or IPv6)                         |
| 2/MED | net/ip/string              | inet_ntoa inet_ntop      | Convert IP from byte form to string                        |
| 2/MED | net/raw_sockets            | SOCK_RAW raw socket      | Uses raw sockets                                           |
+-------+----------------------------+--------------------------+------------------------------------------------------------+
```

## 3CX Supply-chain verification

Let's say you are a company like 3CX, and publish a libffmpeg.dylib library. Your CI system knows that the capabilities include:

```
+------+----------------------+---------+-------------------------------------------+
| RISK |         KEY          | EXAMPLE |                DESCRIPTION                |
+------+----------------------+---------+-------------------------------------------+
|    1 | crypto/algorithm/aes | AES     | Uses the Go crypto/aes library            |
|    1 | fs/directory/create  | mkdir   | Uses libc functions to create directories |
|    1 | fs/ref/tmp           | /tmp    | References /tmp                           |
|    1 | proc/create          | clone   | Create a new child process using clone    |
+------+----------------------+---------+-------------------------------------------+
```

One day, your CI breaks because the capabilities of libffmpeg.dylib changed unexpectedly to:

```
+------+----------------------+----------------------------+------------------------------------------------------------------+
| RISK |         KEY          |           VALUES           |                           DESCRIPTION                            |
+------+----------------------+----------------------------+------------------------------------------------------------------+
|    1 | compression/gzip     | gzip                       | Works with gzip files                                            |
|    1 | crypto/algorithm/aes | AES                        | Uses the Go crypto/aes library                                   |
|    1 | exec/pipe            | _pclose _popen             | Uses popen to launch a program and pipe output to/from it        |
|    1 | fs/directory/create  | mkdir                      | Uses libc functions to create directories                        |
|    1 | fs/lock/update       | flock                      | apply or remove an advisory lock on a file                       |
|    1 | fs/permission/modify | _chmod                     | Modifies file permissions using chmod                            |
|    1 | fs/ref/tmp           | /tmp                       | References /tmp                                                  |
|    1 | kernel/hostname/get  | gethostname                | gets the hostname of the machine                                 |
|    1 | proc/create          | clone                      | Create a new child process using clone                           |
|    1 | random/insecure      | _rand srand                | generate random numbers insecurely                               |
|    1 | sync/semaphore/user  | semaphore_create semapho.. | uses semaphores to synchronize data between processes or threads |
+------+----------------------+----------------------------+------------------------------------------------------------------+
```

That's a good sign to look into the root of the update. And yes, that is real output from bincapz using real samples.

## Usage

```
bincapz <path...>
```

Some flags are accepted:

- --all: Ignore nothing, show all
- --format: table, simple, json, yaml (default: table)
- --ignore-tags: rule tags to ignore (default: harmless)

By default, bincapz filters out "harmless" capabilities, such as calling "stat()" on a file.

## Related Programs

### CAPA

Much of bincapz's functionality is inspired by https://github.com/mandiant/capa. Unfortunately, capa only works on x86-64 binaries (ELF/PE), and does not work for macOS Mach-O programs, arm64 binaries, or scripting languages. It's a pretty amazinng tool though - check it out!
