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
    description = "Gathers hardware information"

  strings:
    $p_system_profiler  = "system_profiler SPHardwareDataType"
    $p_ioreg            = "ioreg -"
    $p_hw_model         = "hw.model"
    $p_machineid        = "machineid.ID"
    $p_machineid_github = "github.com/denisbrodbeck/machineid"

  condition:
    filesize < 157286400 and any of ($p_*)
}
