rule MD5 {
  meta:
    description = "Uses the MD5 signature format"

  strings:
    $ref  = /MD5_[\w\:]{0,16}/
    $ref2 = /md5:[\w\:]{0,16}/

  condition:
    any of them
}

rule md5_verify: medium {
  meta:
    description              = "Verifies MD5 signatures"
    hash_2024_Downloads_4b97 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"

  strings:
    $ref  = "md5 expect"
    $ref2 = "md5 mismatch"
    $ref3 = "FileMd5"
    $ref4 = "FileMD5"

  condition:
    any of them
}
