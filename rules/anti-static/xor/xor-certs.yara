
rule xor_certs : high {
  meta:
    description = "key material obfuscated using xor"
    hash_2023_ZIP_locker_AArch_64 = "724eb1c8e51f184495cfe81df7049531d413dd3e434ee3506b6cc6b18c61e96d"
    hash_2023_ZIP_locker_ARMv5_32 = "0a2bffa0a30ec609d80591eef1d0994d8b37ab1f6a6bad7260d9d435067fb48e"
    hash_2023_ZIP_locker_ARMv6_32 = "e77124c2e9b691dbe41d83672d3636411aaebc0aff9a300111a90017420ff096"
  strings:
    $public = "PUBLIC" xor(1-31)
    $public2 = "PUBLIC" xor(33-255)
    $private = "PRIVATE" xor(1-31)
    $private2 = "PRIVATE" xor(33-255)
    $ssh = "ssh-rsa AAA" xor(1-31)
    $ssh2 = "ssh-rsa AAA" xor(33-255)
  condition:
    any of them
}
