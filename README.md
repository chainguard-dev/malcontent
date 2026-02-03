# malcontent

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/gojp/goreportcard/blob/master/LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/chainguard-dev/malcontent?include_prereleases)](https://github.com/chainguard-dev/malcontent/releases/latest)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9633/badge)](https://www.bestpractices.dev/projects/9633)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/chainguard-dev/malcontent/badge)](https://scorecard.dev/viewer/?uri=github.com/chainguard-dev/malcontent)
[![Go Report Card](https://goreportcard.com/badge/chainguard-dev/malcontent)](https://goreportcard.com/report/chainguard-dev/malcontent)

---

```bash
#
#                   8                       o                 o
#                   8                       8                 8
#    ooYoYo. .oPYo. 8 .oPYo. .oPYo. odYo.  o8P .oPYo. odYo.  o8P
#    8' 8  8 .oooo8 8 8    ' 8    8 8' `8   8  8oooo8 8' `8   8
#    8  8  8 8    8 8 8    . 8    8 8   8   8  8.     8   8   8
#    8  8  8 `YooP8 8 `YooP' `YooP' 8   8   8  `Yooo' 8   8   8
#    ..:..:..:.....:..:.....::.....:..::..::..::.....:..::..::..:
#    ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#    ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#
#    subtle malware discovery tool
```

---

malcontent discovers supply-chain compromises through the magic of context, differential analysis, and YARA.

malcontent has 3 modes of operation:

- [analyze](#analyze): unfiltered analysis of a program's capabilities
- [diff](#diff): risk-weighted differential analysis between two sources
- [scan](#scan): threshold-based scan of a program's capabilities

malcontent is at its best analyzing programs that run on Linux. Still, it also performs admirably for programs designed for other UNIX platforms such as macOS and, to a lesser extent, Windows.

## Features

* 14,500+ YARA rules including third-party rules from:
  * Avast
  * Elastic
  * FireEye
  * Mandiant
  * Nextron
  * ReversingLabs
* Analyzes binary files in most common formats (a.out, ELF, Mach-O, PE)
* Analyzes code from most common languages (AppleScript, C, Go, Javascript/Typescript, PHP, Perl, Python, Ruby, Shell, Typescript)
* Transparent support for archives and container images
* Multiple output formats (JSON, YAML, Markdown, Text, Terminal/TUI)
* Designed to work as part of a CI/CD pipeline
* Embedded rules to support air-gapped networks

## Configuration

```text
GLOBAL OPTIONS:
   --all                       Ignore nothing within a provided scan path
   --exit-extraction           Exit when encountering file extraction errors
   --exit-first-miss           Exit with error if scan source has no matching capabilities
   --exit-first-hit            Exit with error if scan source has matching capabilities
   --format string             Output format (interactive, json, markdown, simple, strings, terminal, yaml) (default: "auto")
   --ignore-self               Ignore the malcontent binary
   --ignore-tags string        Rule tags to ignore (default: "false_positive,ignore")
   --include-data-files        Include files that are detected as non-program (binary or source) files
   --jobs int, -j int          Concurrently scan files within target scan paths (default: 12)
   --max-depth int             Maximum depth for archive extraction (-1 for unlimited) (default: 32)
   --max-files int             Maximum number of files to scan (-1 for unlimited) (default: 2097152)
   --min-file-level int        Obsoleted by --min-file-risk (default: -1)
   --min-file-risk string      Only show results for files which meet the given risk level (any, low, medium, high, critical) (default: "low")
   --min-level int             Obsoleted by --min-risk (default: -1)
   --min-risk string           Only show results which meet the given risk level (any, low, medium, high, critical) (default: "low")
   --oci-auth                  Use Docker Keychain authentication to pull images (warning: may leak credentials to malicious registries!)
   --output string, -o string  Write output to specified file instead of stdout
   --profile, -p               Generate profile and trace files
   --quantity-increases-risk   Increase file risk score based on behavior quantity
   --stats, -s                 Show scan statistics
   --third-party               Include third-party rules which may have licensing restrictions
   --verbose                   Emit verbose logging messages to stderr
   --help, -h                  show help
   --version, -v               print the version
```

> Using `--oci-auth` leverages the Docker Keychain to authenticate image pulls.  
> This option may expose sensitive auth tokens to a malicious registry but is not materially different from other image pull mechanisms (e.g., Docker or `google/go-containerregistry` which malcontent leverages via the `crane` package).  
> Malcontent defaults to anonymous pulls and authentication is opt-in when needing to scan OCI images from private, trusted registries.

## Modes

### Analyze

To enumerate the capabilities of a program, use `mal analyze`. 

malcontent is pretty paranoid in this mode as well as `scan` given the lack of differential context, so expect some false positives.

For example:
![analyze screenshot](./images/analyze.png)

`mal analyze` emits a list of capabilities often seen in malware, categorized by risk level. It works with programs in a wide variety of file formats and scripting languages.

> `CRITICAL` findings should be considered malicious. 

```text
NAME:
   malcontent analyze - fully interrogate a path

USAGE:
   malcontent analyze [options]

OPTIONS:
   --image string, -i string [ --image string, -i string ]  Scan one or more images
   --processes                                              Scan the commands (paths) of running processes
   --help, -h                                               show help
```

### Diff

```text
 ________      ________      ________      ________
|        |    |        |    |        |    |        |
| v1.0.0 | => | v1.0.1 | => | v1.0.2 | => | v1.0.3 |
|________|    |________|    |________|    |________|

               unchanged     HIGH-RISK     decreased
               risk          increase      risk

```

malcontent's most powerful method for discovering malware is through differential analysis against CI/CD artifacts. When used within a build system, malcontent has two significant contextual advantages over a traditional malware scanner:

* Baseline of expected behavior (previous, known-good release)
* Semantic versioning that describes how large of a change to expect

Using the [3CX Compromise](https://www.fortinet.com/blog/threat-research/3cx-desktop-app-compromised) as an example, malcontent trivially surfaces unexpectedly high-risk changes to  libffmpeg:

![diff screenshot](./images/diff.png)

Each line that begins with a "+" represents a new behavior; each behavior has a risk score based on how unique it is to malware.

Like the `diff(1)` command it is based on, malcontent can diff two binaries or directories. Additionally, malcontent can also diff two archive files and even OCI images.

```text
NAME:
   malcontent diff - scan and diff two paths

USAGE:
   malcontent diff [options]

OPTIONS:
   --file-risk-change             Only show diffs when file risk changes
   --file-risk-increase           Only show diffs when file risk increases
   --image, -i                    Scan an image
   --report, -r                   Diff existing analyze/scan reports
   --sensitivity int, --sens int  Control the sensitivity when diffing two files, paths, etc. (default: 5)
   --help, -h                     show help
```

### Scan

malcontent's most basic feature scans targets for possible malware with a default risk threshold of `HIGH` (i.e., harmless, low, and medium behaviors or files are filtered out).

![scan screenshot](./images/scan.png)

```text
NAME:
   malcontent scan - tersely scan a path and return findings of the highest severity

USAGE:
   malcontent scan [options]

OPTIONS:
   --image string, -i string [ --image string, -i string ]  Scan one or more images
   --processes                                              Scan the commands (paths) of running processes
   --help, -h                                               show help
```

## Installation

### Container

`docker pull cgr.dev/chainguard/malcontent:latest`

### Local

Requirements:

* [Go](https://go.dev/dl) - the programming language
* [Rust](https://rust-lang.org/tools/install/) - YARA-X requirement
* [YARA-X](https://virustotal.github.io/yara-x/docs/intro/installation/) - Rust implementation of YARA
* [pkgconf](https://github.com/pkgconf/pkgconf) - required by Go to find C dependencies, included in many UNIX distributions
* [libssl-dev](https://packages.debian.org/sid/libssl-dev) package
* [UPX](https://upx.github.io/)* - required for refreshing sample testdata

> \* By default, malcontent will look for a UPX binary at /usr/bin/upx; to specify a different, [trusted] location, use `MALCONTENT_UPX_PATH=/path/to/upx`

To install YARA-X, first install Rust and then run `make install-yara-x` which will clone the YARA-X repository and install its dependencies and C API.

### Building locally in Debian/Ubuntu

1. Install the dependencies. On Debian/Ubuntu you can run:

   ```bash
   sudo apt-get install -y pkgconf libssl-dev
   ```

   Make sure [Go](https://go.dev/doc/install) and [Rust](https://www.rust-lang.org/tools/install) are installed

1. Run `make install-yara-x` to build the yara-x C API. (The
   `yara_xcapi.pc` file will be generated under `./out/lib/pkgconfig`.
   
    For more information about the yara-x C API, reference the documentation here: https://virustotal.github.io/yara-x/docs/api/c/c-/#building-the-c-library.).

1. Build the malcontent binary with:

    ```bash
    make out/mal
    ```

    The resulting binary is `out/mal`.  

1. Install the binary (optional):

    ```bash
    sudo install out/mal /usr/local/bin
    ```

## Help Wanted

malcontent is open source! If you are interested in contributing, check out [our development guide](DEVELOPMENT.md). Send us a pull request, and we'll help you with the rest!

## ⚠️ Malware Disclaimer ⚠️

Due to how malcontent operates, other malware scanners can detect malcontent as malicious.

Programs that leverage YARA will often see other programs that also use YARA as malicious due to the strings looking for problematic behavior(s).

For example, Elastic's agent has historically detected malcontent because of this: https://github.com/chainguard-dev/malcontent/issues/78.

>  \*Additional scanner findings can be seen in [this](https://www.virustotal.com/gui/file/b6f90aa5b9e7f3a5729a82f3ea35f96439691e150e0558c577a8541d3a187ba4/detection) VirusTotal scan.
