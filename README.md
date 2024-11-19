# malcontent

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/gojp/goreportcard/blob/master/LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/chainguard-dev/malcontent?include_prereleases)](https://github.com/chainguard-dev/malcontent/releases/latest)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9633/badge)](https://www.bestpractices.dev/projects/9633)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/chainguard-dev/malcontent/badge)](https://scorecard.dev/viewer/?uri=github.com/chainguard-dev/malcontent)
[![Go Report Card](https://goreportcard.com/badge/chainguard-dev/malcontent)](https://goreportcard.com/report/chainguard-dev/malcontent)

```text
 _ _    _.  .    _   _    _  .  ___   _.   _  .  ___
( | )  (_|  |_  (_  (_)  ( \_)   |   (/_  ( \_)   |

            subtle malware discovery tool
```

malcontent detects supply-chain compromises and other malicious software. It has 3 modes of operation:

* ✨`diff`: show the risk-weighted capability drift between two versions of a program
  * ☝️ **Our bread & butter: malcontent does this better than anyone else**
* 🕵️‍♀️ `analyze`: deep analysis of a program's capabilities
* 🔍 `scan`: find malicious content across a broad set of file formats

malcontent is a bit paranoid and prone to false positives. It is currently focused on finding threats that impact Linux and macOS platforms, but malcontent can also detect threats that impact other platforms.

## Features

* 14,500+ [YARA](YARA) detection rules
  * Including third-party rules from companies such as Avast, Elastic, FireEye, Mandiant, Nextron, ReversingLabs, and more!
* Analyzes binaries from nearly any operating system (Linux, macOS, FreeBSD, Windows, etc.)
* Analyzes scripts (Python, shell, Javascript, Typescript, PHP, Perl, AppleScript)
* Analyzes container images
* Transparent archive support (apk, tar, zip, etc.)
* Multiple output formats (JSON, YAML, Markdown, Terminal)
* Designed to work as part of a CI/CD pipeline
* Supports air-gapped networks

## Modes

### Scan

Scan directories for possible malware. This is our simplest feature, but not particularly novel either. malcontent is pretty paranoid in this mode, so expect some false positives:

![scan screenshot](./images/scan.png)

You can also scan a container image: `mal scan -i cgr.dev/chainguard/nginx:latest`

Useful flags:

* `--include-data-files`: Include files that do not appear to be programs
* `--processes`: scan active process binaries (experimental)

### Analyze

To analyze the capabilities of a program, use `mal analyze`. For example:

![analyze screenshot](./images/analyze.png)

The analyze mode emits a list of capabilities often seen in malware, categorized by risk level. It works with programs in a wide variety of file formats and scripting languages.

`CRITICAL` findings should be considered malicious. Useful flags include:

* `--format=json`: output to JSON for data parsing
* `--min-risk=high`: only show high or critical risk findings

### Diff

To detect unexpected capability changes, try `diff` mode. This allows you to find far more subtle attacks than a general scan, as you generally have both a baseline "known good" version and the context to understand what capabilities a program needs to operate.

Using the [3CX Compromise](https://www.fortinet.com/blog/threat-research/3cx-desktop-app-compromised) as an example, we're able to use malcontent to detect malicious code inserted in an otherwise harmless library:

![diff screenshot](./images/diff.png)

Each line that begins with a "++" represents a newly added capability. You can use it to diff entire directories recursively, even if they contain programs written in a variety of languages.

For use in CI/CD pipelines, you may find the following flags helpful:

* `--format=markdown`: output in markdown for use in GitHub Actions
* `--min-file-risk=critical`: only show diffs for critical-level changes
* `--quantity-increases-risk=false`: disable heuristics that increase file criticality due to result frequency
* `--file-risk-change`: only show diffs for modified files when the source and destination files are of different risks
* `--file-risk-increase`: only show diffs for modified files when the destination file is of a higher risk than the source file

## Installation

### Container

`docker pull cgr.dev/chainguard/malcontent:latest`

### Local

Requirements:

* [yara](https://virustotal.github.io/yara/) - the rule language
* [go](https://go.dev/) - the programming language
* [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/) - for dependency handling, included in many UNIX distributions

For example, to install the YARA library on Linux or macOS:

```shell
brew install yara || sudo apt install libyara-dev \
 || sudo dnf install yara-devel || sudo pacman -S yara
```

Install malcontent:

```shell
go install github.com/chainguard-dev/malcontent/cmd/mal@latest
```

## Help Wanted

malcontent is an honest-to-goodness open-source project. If you are interested in contributing, check out [DEVELOPMENT.md](DEVELOPMENT.md). Send us a pull request, and we'll help you with the rest!
