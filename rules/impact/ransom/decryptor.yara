rule decryptor: medium {
  meta:
    description = "References 'decryptor'"

  strings:
    $ref = "decryptor"

  condition:
    filesize < 20MB and any of them
}
