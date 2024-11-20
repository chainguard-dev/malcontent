rule encrypt: medium {
  meta:
    description = "encrypts data"

  strings:
    $encrypt = /[\w ]{0,16}Encrypt[\w ]{0,16}/

    $not_encrypted = "Encrypted"

  condition:
    $encrypt and none of ($not*)
}

rule file_crypter: medium {
  meta:
    description = "Encrypts files"

  strings:
    $ref  = "Files encrypted"
    $ref2 = "Encrypting file"
    $ref3 = "encrypts files"
    $ref4 = "files_encrypted"
    $ref5 = "EncryptFile"
    $ref6 = "cryptor" fullword

  condition:
    any of them
}
