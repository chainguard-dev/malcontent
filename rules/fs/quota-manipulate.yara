rule quotactl {
  meta:
    capability  = "CAP_SYS_SYSADMIN"
    description = "manipulate disk quota"
    syscall     = "quotactl"

  strings:
    $ref = "quotactl" fullword

  condition:
    any of them
}
