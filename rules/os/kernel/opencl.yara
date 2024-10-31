
rule OpenCL : medium {
  meta:
    description = "support for OpenCL"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2023_Linux_Malware_Samples_0d79 = "0d7960a39b92dad88986deea6e5861bd00fb301e92d550c232aebb36ed010e46"
  strings:
    $ref = "OpenCL" fullword
  condition:
    any of them
}
