rule chromium_master_password: high {
  meta:
    description = "Decrypts Chromium master password"

  strings:
    $local_state   = "Local State"
    $encrypted_key = "encrypted_key"
    $os_crypt      = "os_crypt"

  condition:
    all of them
}
