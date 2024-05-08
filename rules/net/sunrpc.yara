
rule sunrpc : medium {
  meta:
    description = "Uses SunRPC / XDR"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
    hash_2023_Linux_Malware_Samples_3668 = "3668b167f5c9083a9738cfc4bd863a07379a5b02ee14f48a10fb1240f3e421a6"
    hash_2023_Linux_Malware_Samples_43fa = "43fab92516cdfaa88945996988b7cfe987f26050516503fb2be65592379d7d7f"
  strings:
    $ref = "xdr_bytes" fullword
    $ref2 = "Incompatible versions of RPC"
  condition:
    any of them
}
