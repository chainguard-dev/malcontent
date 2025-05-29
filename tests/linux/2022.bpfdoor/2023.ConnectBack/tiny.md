## linux/2022.bpfdoor/2023.ConnectBack/tiny [😈 CRITICAL]

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| CRITICAL | [anti-static/elf/header](https://github.com/chainguard-dev/malcontent/blob/main/rules/anti-static/elf/header.yara#single_load_rwe) | Binary with a single LOAD segment marked RWE, by Tenable | |
| MEDIUM | [anti-static/binary/opaque](https://github.com/chainguard-dev/malcontent/blob/main/rules/anti-static/binary/opaque.yara#opaque_binary) | binary contains little text content | |

