rule windows_ntlm_auth: medium {
  meta:
    description = "supports Windows NTLM authentication"

  strings:
    $s_ntlmssp   = "ntlmssp" fullword
    $s_smbhash   = "SMBHASH"
    $s_hash_pass = "HASH PASS"
    $s_ntlm_hash = "LM HASH"
    $ntlm        = "ntlm" fullword
    $NTLM        = "NTLM" fullword

  condition:
    any of them
}
