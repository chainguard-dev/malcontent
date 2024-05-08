
rule whirlpool : notable {
  meta:
    description = "hash function often used for cryptomining"
    ref = "https://en.wikipedia.org/wiki/Whirlpool_(hash_function)"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
  strings:
    $ref = "WHIRLPOOL" fullword
  condition:
    any of them
}
