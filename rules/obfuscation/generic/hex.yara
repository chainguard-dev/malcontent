
rule excessive_hex_refs : high {
  meta:
    description = "excessive references to hexadecimal values"
  strings:
    $x = /0x[\dabcdefABCDEF]{2,8}/
  condition:
    filesize < 1MB and #x > 64
}
