# bincapz (proof of concept)

Fast capability enumeration of binaries through static analysis. Powered by YARA rules.

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
- fs/directory/modify
```

One day, your CI breaks because the capabilities have changed unexpectedly to:

```
- exec/pipe
- fs/lock/update
- fs/permission/modify
- kernel/hostname/get
- random/insecure/generate
- random/insecure/seed
- time/clock/sleep
```

Would you research it?

## Usage

```
go run ./cmd/bincapz /sbin/ping
```

## Related Programs

### CAPA

bincapz's hierarchy of capabilities are inspired by https://github.com/mandiant/capa. bincapz aims to support a wider variety of programs more efficiently.

