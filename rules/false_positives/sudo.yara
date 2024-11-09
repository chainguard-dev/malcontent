rule sudo: override linux {
  meta:
    description = "sudo"
    proc_c_exe  = "medium"

  strings:
    $ref = "SUDO_INTERCEPT_FD"

  condition:
    any of them
}
