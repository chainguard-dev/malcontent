rule linux_dmidecode_hardware_profiler: medium linux {
  meta:
    description = "uses dmidecode to query for hardware information"

  strings:
    $ref = /dmidecode[ -\\w]{0,32}/

  condition:
    $ref
}
