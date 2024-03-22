# bincapz

![bincapz logo](./images/logo_small.jpg)

Enumerates program capabilities and malicious behaviors using fragment analysis.

![screenshot](./images/screenshot.png)

## Features

- Analyzes binaries from any architecture - arm64, amd64, riscv, ppc64, sparc64
- Supports scripting languages such as bash, PHP, Perl, Ruby, NodeJS, and Python
- Integrates [YARA forge](https://yarahq.github.io/) for rules by Avast, Elastic, FireEye, Google, Nextron, and others.
- 12,000+ rules that detect everything from ioctl's to malware
- Tuned for especially excellent performance with Linux programs
- Diff-friendly output in Markdown, JSON, YAML outputs
- CI/CD friendly

## Shortcomings

- Does not attempt to process archive files (jar, zip, apk)
- Minimal rule support for Windows and Java (help wanted!)

## Requirements

* go 1.21+
* yara 4.3+ library - you can use this one-liner to install it if necessary:
  
```shell
brew install yara || sudo apt install libyara-devel \
  || sudo dnf install yara-devel || sudo pacman -S yara
```

## Installation

```shell
go install github.com/chainguard-dev/bincapz@latest
```

## Usage

To inspect a binary, pass it as an argument to dump a list of predicted capabilities:

```shell
bincapz /bin/ping
```

There are flags for controlling output (see the Usage section) and filtering out rules. Here's the `--format=markdown` output:


| RISK  |          KEY          |                      DESCRIPTION                       |
|-------|-----------------------|--------------------------------------------------------|
| meta  | entitlements          | com.apple.private.network.management.data.development  |
|       |                       | com.apple.security.network.client                      |
|       |                       | com.apple.security.network.server                      |
| meta  | format                | macho                                                  |
|       |                       |                                                        |
| 1/LOW | net/hostname/resolve  | resolves network hosts via name                        |
| 1/LOW | net/icmp              | iCMP (Internet Control Message Protocol), aka ping     |
| 1/LOW | net/interface/get     | get network interfaces by name or index                |
| 1/LOW | net/interface/list    | list network interfaces and their associated addresses |
| 1/LOW | net/ip                | access the internet                                    |
| 1/LOW | net/ip/multicast/send | send data to multiple nodes simultaneously             |
| 1/LOW | net/ip/resolve        | resolves network hosts via IP address                  |
| 1/LOW | net/ip/send/unicast   | send data to the internet                              |
| 1/LOW | net/socket/connect    | initiate a connection on a socket                      |
| 1/LOW | net/socket/receive    | receive a message from a socket                        |
| 1/LOW | net/socket/send       | send a message to a socket                             |
| 1/LOW | process/userid/set    | set real and effective user ID of current process      |
| 2/MED | combo/net/scan_tool   | may scan networks: "connect                            |
|       |                       | gethostbyname                                          |
|       |                       | port                                                   |
|       |                       | scan                                                   |
|       |                       | socket"                                                |
| 2/MED | net/ip/string         | converts IP address from byte to string                |


Behaviors are sorted by lowest to highest risk: this binary doesn't have anything particularly exciting about it. If you want to only show output for the most suspicious behaviors, use `--min-level=3`, which shows only "HIGH" or "CRITICAL" risk behaviors.

## Diff mode to detect supply-chain attacks

Let's say you are a company that is sensitive to supply-chain compromises. You want to make sure an update doesn't introduce unexpected capability changes. There's a `--diff` mode for that:

```shell
bincapz -diff old_ffmpeg.dylib new_ffmpeg.dylib
```

Here is a result using the 3CX compromise as a test case. Each of the lines that beginsl with a "+" represent a newly added capability.

## 🐙 changed behaviors: testdata/macOS/libffmpeg.dirty.dylib

|  RISK   |                     KEY                      |                                                                   DESCRIPTION                                                                    |
|---------|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| +1/LOW  | **compression/gzip**                         | works with gzip files                                                                                                                            |
| +1/LOW  | **env/HOME**                                 | looks up the HOME directory for the current user                                                                                                 |
| +1/LOW  | **fs/lock/update**                           | apply or remove an advisory lock on a file                                                                                                       |
| +1/LOW  | **kernel/dispatch/semaphore**                | uses Dispatch Semaphores                                                                                                                         |
| +1/LOW  | **kernel/hostname/get**                      | gets the hostname of the machine                                                                                                                 |
| +1/LOW  | **net/http/accept/encoding**                 | able to decode multiple forms of HTTP responses (example: gzip)                                                                                  |
| +1/LOW  | **random/insecure**                          | generate random numbers insecurely                                                                                                               |
| +1/LOW  | **sync/semaphore/user**                      | uses semaphores to synchronize data between processes or threads                                                                                 |
| +2/MED  | **exec/pipe**                                | uses popen to launch a program and pipe output to/from it                                                                                        |
| +2/MED  | **fs/permission/modify**                     | modifies file permissions                                                                                                                        |
| +2/MED  | **net/http/cookies**                         | able to access HTTP resources using cookies                                                                                                      |
| +2/MED  | **net/url/request**                          | requests resources via URL                                                                                                                       |
| +2/MED  | **ref/path/hidden**                          | references a hidden file that can be generated dynamically: "%s/.main_storage"                                                                   |
| +2/MED  | **shell/arbitrary_command/dev_null**         | runs arbitrary commands redirecting output to /dev/null                                                                                          |
| +4/CRIT | **3P/godmoderules/iddqd/god/mode**           | detects a wide array of cyber threats, from malware and ransomware to advanced persistent threats (APTs), by Florian Roth                        |
| +4/CRIT | **3P/signature_base/3cxdesktopapp/backdoor** | detects 3CXDesktopApp MacOS Backdoor component, by X__Junior (Nextron Systems)                                                                   |
| +4/CRIT | **3P/signature_base/nk/3cx**                 | detects malicious DYLIB files related to 3CX compromise, by Florian Roth (Nextron Systems)                                                       |
| +4/CRIT | **3P/signature_base/susp/xored**             | detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key, by Florian Roth |
| +4/CRIT | **3P/volexity/iconic**                       | detects the MACOS version of the ICONIC loader., by threatintel@volexity.com    

If you like to do things the hard way, you can also store the JSON output and diff the keys by hand:

```shell
bincapz --format=json <file> | jq  '.Files.[].Behaviors | keys'
```

## Supported Flags

* `--all`: Ignore nothing, show all
* `--data-files`: include files that are detected to as non-program (binary or source) files
* `--diff`: show capability drift between two files
* `--format` string: Output type. Valid values are: json, markdown, simple, terminal, yaml (default "terminal")
* `--ignore-tags` string: Rule tags to ignore
* `--min-level`: minimum suspicion level to report (1=low, 2=medium, 3=high, 4=critical) (default 1)
* `--omit-empty`: omit files that contain no matches
* `--third-party`: include third-party rules, which may have licensing restrictions (default true)

## FAQ

### How does it work?

bincapz behaves similarly to the initial triage step most security analysts use when faced with an unknown binary: a cursory `strings` inspection. bincapz has several advantages over human analysis: the ability to match raw byte sequences, decrypt data, and a library of 12,000+ YARA rules that combines the experience of security engineers worldwide.

This strategy works, as every program leaves traces of its capabilities in its contents, particularly on UNIX platforms. These fragments are typically  `libc` or `syscall` references or error codes. Scripting languages are easier to analyze due to their cleartext nature and are also supported. 

### Why not properly reverse-engineer binaries?

Mostly because fragment analysis is so effective. Capability analysis through reverse engineering is challenging to get right, particularly for programs that execute other programs, such as malware that executes `/bin/rm`. Capability analysis through reverse engineering that supports a wide array of file formats also requires significant engineering investment.

### Why not just observe binaries in a sandbox?

The most exciting malware only triggers when the right conditions are met. Nation-state actors, in particular, are fond of time bombs and locale detection. bincapz will enumerate the capabilities, regardless of conditions.

### Why not just analyze the source code?

Sometimes you don't have it! Sometimes your CI/CD infrastructure is the source of compromise. Source-code-based capability analysis is also complicated for polyglot programs, or programs that execute external binaries, such as `/bin/rm`.

### How does bincapz work for packed binaries (UPX)?

bincapz alerts when an obfuscated or packed binary is detected, such as those generated by [upx](https://github.com/upx/upx). Fragment analysis may still work to a lesser degree. For the full story, we recommend unpacking binaries first.

### What related software is out there?

bincapz was initially inspired by [mandiant/capa](https://github.com/mandiant/capa). While capa is a fantastic tool, it only works on x86-64 binaries (ELF/PE), and does not work for macOS programs, arm64 binaries, or scripting languages. <https://karambit.ai/> and <https://www.reversinglabs.com/> offer capability analysis through reverse engineering as a service. If you require more than what bincapz can offer, such as Windows binary analysis, you should check them out.

### How can I help?

If you find malware that `bincapz` doesn't surface suspicious behaviors for, send us a patch! All of the rules are defined in YARA format, and can be found in the `rules/` folder.

### Error: ld: library 'yara' not found

If you get this error at installation:

```
ld: library 'yara' not found
```

You'll need to install the `yara` C library:

```
brew install yara || sudo apt install libyara-devel || sudo dnf install yara-devel || sudo pacman -S yara
```
