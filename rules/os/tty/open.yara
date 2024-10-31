rule openpty: medium {
  meta:
    description                          = "finds and opens an available pseudoterminal"
    hash_2024_Downloads_8cad             = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2023_Linux_Malware_Samples_14a3 = "14a33415e95d104cf5cf1acaff9586f78f7ec3ffb26efd0683c468edeaf98fd7"
    hash_2023_Linux_Malware_Samples_6de1 = "6de1e587ac4aa49273042ffb3cdce5b92b86c31c9f85ca48dae8a38243515f75"

  strings:
    $ref  = "openpty" fullword
    $ref2 = "pty.Open"

  condition:
    any of them
}
