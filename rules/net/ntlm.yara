
rule windows_ntlm : notable {
  meta:
    description = "Uses the Windows NTLM authentication scheme"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2023_Linux_Malware_Samples_1020 = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"
    hash_2023_Linux_Malware_Samples_24f3 = "24f3ac76dcd4b0830a1ebd82cc9b1abe98450b8df29cb4f18f032f1077d24404"
  strings:
    $s_ntlmssp = "ntlmssp"
    $s_smbhash = "SMBHASH"
    $s_hash_pass = "HASH PASS"
    $s_ntlm_hash = "LM HASH"
  condition:
    any of ($s*)
}
