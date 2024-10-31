rule sysctl_machdep {
  meta:
    description = "gets detailed hardware information using sysctl"

  strings:
    $ref  = "kern.osproductversion"
    $ref2 = "machdep.cpu.vendor"
    $ref3 = "machdep.cpu.brand_string"
    $ref4 = "hw.cpufrequency"

  condition:
    any of them
}

rule macos_hardware_profiler: medium {
  meta:
    description              = "Gathers hardware information"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"

  strings:
    $p_system_profiler  = "system_profiler SPHardwareDataType"
    $p_uuid             = "IOPlatformUUID"
    $p_ioreg            = "ioreg -"
    $p_hw_model         = "hw.model"
    $p_machineid        = "machineid.ID"
    $p_machineid_github = "github.com/denisbrodbeck/machineid"

  condition:
    filesize < 157286400 and any of ($p_*)
}
