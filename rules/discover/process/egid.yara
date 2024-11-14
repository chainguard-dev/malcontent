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

  strings:
    $getmygid = "getmygid"

  condition:
    any of them
}
