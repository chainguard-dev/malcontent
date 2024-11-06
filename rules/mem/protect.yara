rule virtualprotect: low windows {
  meta:
    description = "Changes the protection of virtual memory within the calling process"

  strings:
    $ref = "VirtualProtect" fullword

  condition:
    any of them
}

rule virtualprotect_ex: medium windows {
  meta:
    description = "Changes the protection of virtual memory within other processes"

  strings:
    $ref = "VirtualProtectEx" fullword

  condition:
    any of them
}
