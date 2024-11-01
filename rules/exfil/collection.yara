rule collect_data: medium {
  meta:
    description                          = "Uses terms that reference data collection"
    hash_2023_Downloads_06ab             = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_04b5 = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"

  strings:
    $ref  = "collect_data"
    $ref2 = "CollectData"
    $ref3 = "DataCollection"

  condition:
    any of them
}
