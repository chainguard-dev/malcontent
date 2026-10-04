rule ignore_sudo: override linux {
  meta:
    description      = "sudo"
    proc_s_exe       = "medium"
    small_elf_sudoer = "medium"
    proc_d_exe_high  = "medium"

  strings:
    $ref  = "SUDO_INTERCEPT_FD"
    $ref2 = "SUDO_EDITOR"

  condition:
    any of them
}

rule sudo_changelog: override {
  meta:
    description          = "/usr/share/doc/sudo/ChangeLog"
    cd_bin               = "low"
    lib_subdir           = "low"
    pam_get_item         = "low"
    etc_initd_short_file = "low"
    ruby_setuid_0        = "low"

  strings:
    $sudo_maintainer = /Todd\.Miller@sudo\.ws/
    $sudo_plugin     = /sudo_plugin/

  condition:
    filesize < 200KB and all of them
}
