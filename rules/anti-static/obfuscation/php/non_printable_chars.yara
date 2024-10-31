rule php_non_printable: medium {
  meta:
    description                                                                               = "non-printable values unexpectedly passed to a function"
    credit                                                                                    = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2023_0xShell_adminer                                                                 = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2023_0xShell_wesoori                                                                 = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2024_UPX_0a07c056fec72668d3f05863f103987cc1aaec92e72148bf16db6cfd58308617_elf_x86_64 = "94f4de1bd8c85b8f820bab936ec16cdb7f7bc19fa60d46ea8106cada4acc79a2"

  strings:
    $ref = /(function|return|base64_decode).{,64}[^\x09-\x0d\x20-\x7E]{3}/
    $php = "<?php"

  condition:
    filesize < 5242880 and all of them
}
