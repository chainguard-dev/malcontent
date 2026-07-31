rule _reboot: harmless {
  meta:
    capability  = "CAP_SYS_BOOT"
    description = "reboot system"

  strings:
    // "_reboot" fullword cannot match inside "master_reboot" - the preceding "r" is
    // a word character - so the $not for it only ever silenced files that also held
    // a real _reboot reference
    $ref = "_reboot" fullword

  condition:
    $ref
}

rule kexec_load {
  meta:
    capability  = "CAP_SYS_BOOT"
    description = "load a new kernel for later execution"

  strings:
    $ref  = "kexec_load" fullword
    $ref2 = "kexec_file_load" fullword

  condition:
    any of them
}

rule reboot_command: medium {
  meta:
    description = "Forcibly reboots machine"

  strings:
    $usr_sbin = "/usr/sbin/reboot" fullword
    $sbin     = "/sbin/reboot" fullword
    $bin      = "/bin/reboot" fullword
    $usr_bin  = "/usr/bin/reboot" fullword

  condition:
    any of them
}
