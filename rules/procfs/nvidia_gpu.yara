
rule proc_nvidia_gpus : notable {
  meta:
    description = "get GPU info"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_04b5 = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
  strings:
    $ref = "/proc/driver/nvidia/gpus" fullword
  condition:
    any of them
}
