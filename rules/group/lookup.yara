
rule getgrent : medium {
  meta:
    description = "get entry from group database"
    hash_2023_Linux_Malware_Samples_1020 = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"
    hash_2023_Linux_Malware_Samples_24f3 = "24f3ac76dcd4b0830a1ebd82cc9b1abe98450b8df29cb4f18f032f1077d24404"
    hash_2023_Linux_Malware_Samples_43fa = "43fab92516cdfaa88945996988b7cfe987f26050516503fb2be65592379d7d7f"
  strings:
    $ref = "getgrent" fullword
    $ref4 = "getgruuid" fullword
    $ref5 = "setgroupent" fullword
    $ref6 = "setgrent" fullword
    $ref7 = "endgrent" fullword
  condition:
    any of them
}

rule getgrgid_nam : harmless {
  meta:
    description = "get entry from group database"
  strings:
    $ref2 = "getgrnam" fullword
    $ref3 = "getgrgid" fullword
  condition:
    any of them
}
