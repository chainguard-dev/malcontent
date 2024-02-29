rule windows_ntlm : notable {
  meta:
	description = "Uses the Windows NTLM authentication scheme"
  strings:
    $s_ntlmssp = "ntlmssp"
    $s_smbhash = "SMBHASH"
    $s_hash_pass = "HASH PASS"
    $s_ntlm_hash = "LM HASH"
  condition:
    any of ($s*)
}
