# bincapz (proof of concept)

Fast capability enumeration of binaries through static analysis. Powered by YARA.

## Features

- Generic support for all binary formats and languages
- Focused on UNIX platforms, like Linux, MacOS, FreeBSD, OpenBSD
- Works for analyzing code written in C, ObjC, Swift, Go, PHP, Python, Perl, and more.
- syscall enumeration
- pledge enumeration
- Linux capability enumeration

## Installation

Requires `yara`

```shell
go install github.com/tstromberg/bincapz@latest
```

## Demo - ping

When run against `/sbin/ping`:

```
+------+-------------------------+------------------------+------------------------------------------------------------+
| RISK |           KEY           |         VALUES         |                        DESCRIPTION                         |
+------+-------------------------+------------------------+------------------------------------------------------------+
|    1 | current_proc/userid/set | setuid                 | set real and effective user ID of process                  |
|    1 | net/hostname/resolve    | gethostbyname2         | Uses libc functions to resolve network hosts               |
|    1 | net/icmp                | ICMP                   | ICMP (Internet Control Message Protocol), aka ping packets |
|    1 | net/interface/get       | if_nametoindex         | libc functions for retrieving network interface            |
|    1 | net/interface/list      | freeifaddrs getifaddrs | list network interfaces and their associated addresses     |
|    1 | net/ip                  | invalid packet         | Internet Protocol user                                     |
|    1 | net/ip/multicast/send   | multicast              | Send data to multiple nodes simultaneously                 |
|    1 | net/ip/resolve          | gethostbyaddr          | Uses libc functions to resolve network hosts               |
|    1 | net/ip/send/unicast     | unicast                | send data to the internet                                  |
|    1 | net/socket              | setsockopt             | set socket options                                         |
|    1 | net/socket/connect      | _connect               | initiate a connection on a socket                          |
|    1 | net/socket/receive      | recvmsg                | receive a message from a socket                            |
|    1 | net/socket/send         | sendmsg                | send a message to a socket                                 |
+------+-------------------------+------------------------+------------------------------------------------------------+```
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
bincapz <path to binary>
```

Some flags are accepted:

- --all: Ignore nothing, show all
- --format: table, simple, json, yaml (default: table)
- --ignore-tags: rule tags to ignore (default: harmless)

By default, bincapz filters out "harmless" capabilities, such as calling "stat()" on a file.

## Related Programs

### CAPA

Much of bincapz's functionality is inspired by https://github.com/mandiant/capa. Unfortunately, Capa only works on x86-64 binaries, ELF/PE, and is exceptionally slow yet thorough.
