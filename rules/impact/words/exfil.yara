
rule exfil : medium {
  meta:
    description = "References 'exfil'"
    hash_2022_safepackage_Confused = "6cd8e92b6429349fdff3c45d30ac6a41b9351616f750930c4eca0af99c6c3008"
    hash_2022_safepackage_Confused = "6cd8e92b6429349fdff3c45d30ac6a41b9351616f750930c4eca0af99c6c3008"
  strings:
    $ref = "exfil" fullword
    $ref2 = "exfiltrate" fullword
  condition:
    any of them
}
