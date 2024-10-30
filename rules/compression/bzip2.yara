rule bzip2 {
  meta:
    description = "Works with bzip2 files"

  strings:
    $ref = "bzip2" fullword

  condition:
    any of them
}
