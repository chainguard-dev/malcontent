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
    description = "Verifies MD5 signatures"

  strings:
    $ref  = "md5 expect"
    $ref2 = "md5 mismatch"
    $ref3 = "FileMd5"
    $ref4 = "FileMD5"

  condition:
    any of them
}
