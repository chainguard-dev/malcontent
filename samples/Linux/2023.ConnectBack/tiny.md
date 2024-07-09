## Linux/2023.ConnectBack/tiny [🚨 CRITICAL]

|  RISK  |                                                                             KEY                                                                              |                       DESCRIPTION                        | EVIDENCE |
|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|----------|
| HIGH   | [evasion/elf/funky/tenable](https://github.com/chainguard-dev/bincapz/blob/main/rules/evasion/elf-funky-tenable.yara#single_load_rwe)                        | Flags binaries with a single LOAD segment marked as RWE. |          |
| HIGH   | [evasion/packer/elf](https://github.com/chainguard-dev/bincapz/blob/main/rules/evasion/packer/elf.yara#obfuscated_elf)                                       | Obfuscated ELF binary (missing content)                  |          |
| MEDIUM | [evasion/binary/opaque](https://github.com/chainguard-dev/bincapz/blob/main/rules/evasion/binary-opaque.yara#opaque_binary)                                  | opaque binary                                            |          |
| LOW    | [evasion/binary/unusually_small](https://github.com/chainguard-dev/bincapz/blob/main/rules/evasion/binary-unusually_small.yara#impossibly_small_elf_program) | impossibly small elf program                             |          |

