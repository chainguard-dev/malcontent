rule hashcat: medium {
  meta:
  strings:
    $ref = "hashcat" fullword

  condition:
    $ref
}
