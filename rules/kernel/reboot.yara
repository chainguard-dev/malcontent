rule _reboot: harmless {
  meta:
    capability  = "CAP_SYS_BOOT"
    description = "reboot system"

  strings:
    $ref        = "_reboot" fullword
    $not_master = "master_reboot"

  condition:
    $ref and none of ($not*)
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
    description               = "Forcibly reboots machine"
    hash_2023_init_d_halt     = "c8acf18e19c56191e220e5f6d29d7c1e7f861b2be16ab8d5da693b450406fd0f"
    hash_2023_rc0_d_S01halt   = "c8acf18e19c56191e220e5f6d29d7c1e7f861b2be16ab8d5da693b450406fd0f"
    hash_2023_rc6_d_S01reboot = "c8acf18e19c56191e220e5f6d29d7c1e7f861b2be16ab8d5da693b450406fd0f"

  strings:
    $usr_sbin = "/usr/sbin/reboot" fullword
    $sbin     = "/sbin/reboot" fullword
    $bin      = "/bin/reboot" fullword
    $usr_bin  = "/usr/bin/reboot" fullword

  condition:
    any of them
}
