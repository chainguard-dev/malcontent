rule getegid: harmless {
  meta:
    syscall     = "getegid"
    description = "returns the effective group id of the current process"

  strings:
    $getuid = "getegid" fullword
    $Getuid = "Getegid" fullword

  condition:
    any of them
}

rule php_getmygid: medium {
  meta:
    syscall     = "getegid"
    description = "returns the effective group id of the current process"

    hash_2023_0xShell_root    = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"


  strings:
    $getmygid = "getmygid"

  condition:
    any of them
}
