
rule monero_pool : medium {
  meta:
    description = "References Monero mining pools"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_04b5 = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
  strings:
    $ref = "monero"
    $ref2 = "pool"
  condition:
    all of them
}
