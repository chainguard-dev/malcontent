## linux/2023.ConnectBack/tiny [🚨 CRITICAL]

|   RISK   |                                                                               KEY                                                                               |                       DESCRIPTION                        | EVIDENCE |
|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|----------|
| CRITICAL | [evasion/elf/sus_header](https://github.com/chainguard-dev/malcontent/blob/main/rules/evasion/elf-sus_header.yara#single_load_rwe)                              | Binary with a single LOAD segment marked RWE, by Tenable |          |
| HIGH     | [evasion/binary/unusually_small](https://github.com/chainguard-dev/malcontent/blob/main/rules/evasion/binary-unusually_small.yara#impossibly_small_elf_program) | ELF binary is unusually small                            |          |
| HIGH     | [evasion/packer/elf](https://github.com/chainguard-dev/malcontent/blob/main/rules/evasion/packer/elf.yara#obfuscated_elf)                                       | Obfuscated ELF binary (missing symbols)                  |          |
| MEDIUM   | [evasion/binary/opaque](https://github.com/chainguard-dev/malcontent/blob/main/rules/evasion/binary-opaque.yara#opaque_binary)                                  | binary contains little text content                      |          |

