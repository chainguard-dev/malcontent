rule lookup_dcookie {
  meta:
    capability  = "CAP_SYS_SYSADMIN"
    description = "return a directory entry's path by cookie"
    syscall     = "lookup_dcookie"

  strings:
    $ref = "lookup_dcookie" fullword

  condition:
    any of them
}
