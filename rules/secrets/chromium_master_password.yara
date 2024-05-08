
rule chromium_master_password : suspicious {
  meta:
    description = "Decrypts Chromium master password"
    hash_2018_CookieMiner_harmlesslittlecode = "7bc657c96c15ec0629740e00a9c7497417b599694c6b7598eeff095136cbd507"
    hash_2024_2024_GitHub_Clipper_main = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"
    hash_2024_2024_GitHub_Clipper_main = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"
  strings:
    $local_state = "Local State"
    $encrypted_key = "encrypted_key"
    $os_crypt = "os_crypt"
  condition:
    all of them
}
