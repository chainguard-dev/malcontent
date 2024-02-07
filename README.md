# bincapz (proof of concept)

Fast capability enumeration of binaries through static analysis. Powered by YARA rules.

## Features

- Generic support for all binary formats and languages
  - Development is currently furthest on MachO (C/ObjC) binaries
- syscall enumeration (IN DEVELOPMENT)
- pledge enumeration (IN DEVELOPMENT)
- Scripting language & source code support (TBD)

## Basic Example

When run against /sbin/ping:

```
/sbin/ping
- net/hostname/resolve
- net/icmp
- net/ip
- net/ip/multicast/send
- net/ip/send
- net/socket
- net/socket/receive
- net/socket/send
- proc/uid/set
```

## 3CX Supply-chain verification

Let's say you are a company like 3CX, and publish a libffmpeg.dylib library. Your CI system knows that the capabilities include:

```
release/libffmpeg.dylib
- fs/directory/create
```

One day, your CI breaks because the capabilities of libffmpeg.dylib changed unexpectedly to:

```
objective-see/SmoothOperator/libffmpeg.dylib
- exec/pipe
- fs/directory/create
- fs/lock/update
- fs/permission/modify
- kernel/hostname/get
- random/insecure/generate
- random/insecure/seed
- sync/semaphore/create
- sync/semaphore/signal
- sync/semaphore/wait
- time/clock/sleep
```

That's a good sign to look into the root of the update. And yes, that is real output from bincapz using real samples.

## Usage

```
go run ./cmd/bincapz /sbin/ping
```

Some flags are accepted:

```
  -all
    	Ignore nothing, show all
  -ignore-tags string
    	Rule tags to ignore (default "harmless")
  -json
    	JSON output
  -rules-dir string
    	Path to rules file (default "rules")
  -yaml
        YAML output
```

By default, bincapz filters out "harmless" capabilities, such as calling "stat()" on a file.

## Related Programs

### CAPA

bincapz's hierarchy of capabilities are inspired by https://github.com/mandiant/capa. bincapz aims to support a wider variety of programs more efficiently.
