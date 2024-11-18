rule ignore_sudo: override linux {
  meta:
    description      = "sudo"
    proc_c_exe       = "medium"
    small_elf_sudoer = "medium"
    proc_d_exe_high  = "medium"

  strings:
    $ref  = "SUDO_INTERCEPT_FD"
    $ref2 = "SUDO_EDITOR"

  condition:
    any of them
}
