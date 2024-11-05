rule excessive_hex_refs: medium {
  meta:
    description = "many references to hexadecimal values"

  strings:
    $x = /0x[\dabcdefABCDEF]{2,8}/
    $y = /\\x[\dabcdefABCDEF]{2,8}/

  condition:
    filesize < 1MB and (#x > 64 or #y > 256)
}

