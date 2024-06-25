
rule getegid : harmless {
  meta:
    syscall = "getegid"
    description = "returns the effective group id of the current process"
  strings:
    $getuid = "getegid" fullword
    $Getuid = "Getegid" fullword
  condition:
    any of them
}

rule php_getmygid : medium {
  meta:
    syscall = "getegid"
    description = "returns the effective group id of the current process"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_root = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
  strings:
    $getmygid = "getmygid"
  condition:
    any of them
}
