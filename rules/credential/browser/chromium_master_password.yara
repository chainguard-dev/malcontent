rule chromium_master_password: high {
  meta:
    description = "Decrypts Chromium master password"


    hash_2024_Ailynitro_1_0_setup    = "f3e9d9bb335b5eda9be33837af006b3ef364390f837bb8bc93c2efafdbf4ec2a"

  strings:
    $local_state   = "Local State"
    $encrypted_key = "encrypted_key"
    $os_crypt      = "os_crypt"

  condition:
    all of them
}
