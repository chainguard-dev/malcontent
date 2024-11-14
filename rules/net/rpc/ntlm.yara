rule windows_ntlm: medium {
  meta:
    description              = "Uses the Windows NTLM authentication scheme"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"

  strings:
    $s_ntlmssp   = "ntlmssp"
    $s_smbhash   = "SMBHASH"
    $s_hash_pass = "HASH PASS"
    $s_ntlm_hash = "LM HASH"

  condition:
    any of ($s*)
}
