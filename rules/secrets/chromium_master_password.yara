
rule chromium_master_password : high {
  meta:
    description = "Decrypts Chromium master password"
    hash_2024_2024_GitHub_Clipper_main = "7faf316a313de14a734b784e6d2ab53dfdf1ffaab4adbbbc46f4b236738d7d0d"
    hash_2024_Ailyboostbot_1_0_setup = "7bf6a5192d9b1ab3c5d8bb11b97963695569922090a0ddf02e1b690c2731aa30"
    hash_2024_Ailynitro_1_0_setup = "f3e9d9bb335b5eda9be33837af006b3ef364390f837bb8bc93c2efafdbf4ec2a"
  strings:
    $local_state = "Local State"
    $encrypted_key = "encrypted_key"
    $os_crypt = "os_crypt"
  condition:
    all of them
}
