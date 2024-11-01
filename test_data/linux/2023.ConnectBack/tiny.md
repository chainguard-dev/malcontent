## linux/2023.ConnectBack/tiny [🚨 CRITICAL]

|   RISK   |                                                                        KEY                                                                        |                       DESCRIPTION                        | EVIDENCE |
|----------|---------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|----------|
| CRITICAL | [anti_static/elf/header](https://github.com/chainguard-dev/malcontent/blob/main/rules/anti-static/elf/header.yara#single_load_rwe)                | Binary with a single LOAD segment marked RWE, by Tenable |          |
| HIGH     | [anti_static/binary/tiny](https://github.com/chainguard-dev/malcontent/blob/main/rules/anti-static/binary/tiny.yara#impossibly_small_elf_program) | ELF binary is unusually small                            |          |
| HIGH     | [anti_static/packer/elf](https://github.com/chainguard-dev/malcontent/blob/main/rules/anti-static/packer/elf.yara#obfuscated_elf)                 | Obfuscated ELF binary (missing symbols)                  |          |
| MEDIUM   | [anti_static/binary/opaque](https://github.com/chainguard-dev/malcontent/blob/main/rules/anti-static/binary/opaque.yara#opaque_binary)            | binary contains little text content                      |          |

