rule hashcat: medium {
  meta:
    description = "References 'hashcat', a password cracking tool"

  strings:
    $ref = "hashcat" fullword

  condition:
    $ref
}
