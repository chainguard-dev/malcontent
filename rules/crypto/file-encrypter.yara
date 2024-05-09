
rule file_crypter : medium {
  meta:
    description = "Encrypts files"
    hash_2023_Downloads_24b5 = "24b5cdfc8de10c99929b230f0dcbf7fcefe9de448eeb6c75675cfe6c44633073"
    hash_2023_Downloads_713b = "713b699c04f21000fca981e698e1046d4595f423bd5741d712fd7e0bc358c771"
    hash_2023_Downloads_8b57 = "8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201"
  strings:
    $ref = "Files encrypted"
    $ref2 = "Encrypting file"
    $ref3 = "encrypts files"
    $ref4 = "files_encrypted"
    $ref5 = "EncryptFile"
    $ref6 = "cryptor" fullword
  condition:
    any of them
}
