rule getuid: harmless {
  meta:
    syscall     = "getuid"
    description = "returns the user id of the current process"

  strings:
    $getuid = "getuid" fullword
    $Getuid = "Getuid" fullword

  condition:
    any of them
}
