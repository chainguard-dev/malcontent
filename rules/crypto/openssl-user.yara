
rule openssl_user : notable {
  meta:
    description = "Uses OpenSSL"
    hash_2024_Downloads_ad5b = "ad5b99bbcb9efe65a47d250497eb5d88d28a53ad0dc5d8989f3da4504b4c00f8"
    hash_2023_Linux_Malware_Samples_6481 = "64815d7c84c249e5f3b70d494791498ce85ea9a97c3edaee49ffa89809e20c6e"
    hash_2023_Linux_Malware_Samples_876b = "876b30a58a084752dbbb66cfcc003417e2be2b13fb5913612b0ca4c77837467e"
  strings:
    $ref = "_EXT_FLAG_SENT"
  condition:
    any of them
}
