rule probably_a_miner : suspicious {
  meta:
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_04b5 = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2023_Linux_Malware_Samples_0d79 = "0d7960a39b92dad88986deea6e5861bd00fb301e92d550c232aebb36ed010e46"
    hash_2023_Linux_Malware_Samples_0dcf = "0dcfa54a7e8a4e631ef466670ce604a61f3b0e8b3e9cf72c943278c0f77c31a2"
    hash_2023_Linux_Malware_Samples_1736 = "1736d6feaa80ee3c7d072a6db7ae5e7ee63c1a10314e46ab46b1a2477063de60"
    hash_2023_Linux_Malware_Samples_19f7 = "19f76bf2be3ea11732f2c5c562afbd6f363b062c25fba3a143c3c6ef4712774b"
    hash_2023_Linux_Malware_Samples_1e48 = "1e48915f40bfdd75fb83e79779010336320af76411b9af9f0e68d361e63a2f60"
  strings:
    $argon = "argon2d"
    $proc_self = "/proc/self"
    $numa = "NUMA"
  condition:
    all of them
}
