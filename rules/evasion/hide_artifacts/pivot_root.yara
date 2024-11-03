rule pivot_root: medium {
  meta:
    capability  = "CAP_SYS_SYSADMIN"
    description = "change the root mount location"
    syscall     = "pivot_root"

  strings:
    $ref       = "pivot_root" fullword
    $not_pivot = "no_pivot_root"

  condition:
    $ref and none of ($not*)
}
