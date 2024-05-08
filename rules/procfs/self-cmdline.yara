
rule proc_self_cmdline : notable {
  meta:
    description = "Gets the command-line associated to this process"
    pledge = "stdio"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2023_Linux_Malware_Samples_139b = "139b09543494ead859b857961d230a39b9f4fc730f81cf8445b6d83bacf67f3d"
    hash_2023_Linux_Malware_Samples_e212 = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
  strings:
    $ref = "/proc/self/cmdline" fullword
  condition:
    any of them
}
