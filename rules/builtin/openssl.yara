
rule openssl : notable {
  meta:
    description = "This binary includes OpenSSL source code"
  strings:
    $ref = "OpenSSL/"
  condition:
    any of them
}

rule elf_with_bundled_openssl : suspicious {
  meta:
    hash_2023_Unix_Malware_Bruteforce_4020 = "4020b018fcebf76672af2824636e7948131b313f723adef6cf41ad06bd2c6a6f"
  strings:
    $aes_part = "AES part of OpenSSL"
  condition:
    uint32(0) == 1179403647 and $aes_part
}
