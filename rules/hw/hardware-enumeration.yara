rule linux_dmidecode_hardware_profiler: medium linux {
  meta:
    hash_2023_Downloads_2f13 = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"

  strings:
    $ref = /dmidecode[ -\w]{0,32}/

  condition:
    $ref
}
