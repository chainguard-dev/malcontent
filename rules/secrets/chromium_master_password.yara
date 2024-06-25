
rule chromium_master_password : high {
  meta:
    description = "Decrypts Chromium master password"
    hash_2024_2024_GitHub_Clipper_main = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"
  strings:
    $local_state = "Local State"
    $encrypted_key = "encrypted_key"
    $os_crypt = "os_crypt"
  condition:
    all of them
}
