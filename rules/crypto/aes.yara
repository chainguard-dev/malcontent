rule crypto_aes {
  meta:
    description = "Supports AES (Advanced Encryption Standard)"

  strings:
    $ref  = "crypto/aes"
    $ref2 = "AES" fullword
    $ref3 = "openssl/aes"
    $ref4 = "aes_256_cbc"
    $ref5 = "aes_encrypt"
    $ref6 = "pyaes" fullword
    $ref7 = "AESModeOfOperationGCM"

  condition:
    any of them
}

rule aes_key_iv: high {
  meta:
    description = "hardcoded AES key/iv pair"

  strings:
    $aes   = "aes" fullword
    $aese2 = "AES" fullword

    $key = /key = [\w\.\(,]{0,32}['"][\w=\/\+]{8,256}['"]/
    $iv  = /iv = [\w\.\(,]{0,32}['"][\w=\/]{8,256}['"]/

  condition:
    any of ($aes*) and ($key and $iv)
}
