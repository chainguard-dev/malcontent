rule geteuid: harmless {
  meta:
    syscall     = "geteuid"
    description = "returns the effective user id of the current process"

  strings:
    $getuid = "geteuid" fullword
    $Getuid = "Geteuid" fullword

  condition:
    any of them
}
