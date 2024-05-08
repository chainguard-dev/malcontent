
rule openssl : notable {
  meta:
    description = "This binary includes OpenSSL source code"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_04b5 = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
  strings:
    $ref = "OpenSSL/"
  condition:
    any of them
}

rule elf_with_bundled_openssl : suspicious {
  meta:
    hash_2023_Unix_Malware_Bruteforce_4020 = "4020b018fcebf76672af2824636e7948131b313f723adef6cf41ad06bd2c6a6f"
    hash_2023_Linux_Malware_Samples_24ee = "24ee0e3d65b0593198fbe973a58ca54402b0879d71912f44f4b831003a5c7819"
    hash_2023_Linux_Malware_Samples_2f85 = "2f85ca8f89dfb014b03afb11e5d2198a8adbae1da0fd76c81c67a81a80bf1965"
  strings:
    $aes_part = "AES part of OpenSSL"
  condition:
    uint32(0) == 1179403647 and $aes_part
}
