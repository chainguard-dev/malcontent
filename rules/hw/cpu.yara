rule sys_devices_cpu: linux medium {
  meta:
    description = "Get information about CPUs"

  strings:
    $ref = "/sys/devices/system/cpu" fullword

  condition:
    any of them
}

rule CpuInfoAndModel: macos medium {
  meta:
    description = "Get information about CPUs"

  strings:
    $ref = "CpuInfoAndModel"

  condition:
    any of them
}

