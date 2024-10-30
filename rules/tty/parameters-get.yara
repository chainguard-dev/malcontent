rule tcgetattr: medium {
  meta:
    description                          = "get terminal parameters"
    hash_2023_Linux_Malware_Samples_3292 = "329255e33f43e6e9ae5d5efd6f5c5745c35a30d42fb5099beb51a6e40fe9bd76"
    hash_2023_Linux_Malware_Samples_6de1 = "6de1e587ac4aa49273042ffb3cdce5b92b86c31c9f85ca48dae8a38243515f75"
    hash_2023_Linux_Malware_Samples_ee22 = "ee22d8b31eecf2c7dd670dde075df199be44ef4f61eb869f943ede7f5c3d61cb"

  strings:
    $ref  = "tcgetaddr" fullword
    $ref2 = "cfgetospeed" fullword

  condition:
    any of them
}
