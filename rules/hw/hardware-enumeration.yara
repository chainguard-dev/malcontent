rule linux_dmidecode_hardware_profiler: medium linux {
  meta:
    hash_2023_Downloads_2f13             = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
    hash_2023_Linux_Malware_Samples_2bc8 = "2bc860efee229662a3c55dcf6e50d6142b3eec99c606faa1210f24541cad12f5"
    hash_2023_Linux_Malware_Samples_75ea = "75ea0d099494b0397697d5245ea6f2b5bf8f22bb3c3e6d6d81e736ac0dac9fbc"

  strings:
    $ref = /dmidecode[ -\w]{0,32}/

  condition:
    $ref
}
