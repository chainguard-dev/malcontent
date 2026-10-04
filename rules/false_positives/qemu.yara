rule qemu: override {
  meta:
    description    = "QEMU"
    proc_d_cmdline = "medium"
    ESET_Moose_2   = "harmless"

  strings:
    $module  = /QEMU_MODULE/
    $aligned = /QEMU_IS_ALIGNED/

  condition:
    filesize < 30MB and any of them
}

rule qemu_openbios: override {
  meta:
    description     = "OpenBIOS firmware ROMs for QEMU SPARC emulation"
    single_load_rwe = "harmless"

  strings:
    $openbios_team = /OpenBiosTeam,OpenBIOS/
    $openbios_dict = /OpenBIOS dictionary:/

  condition:
    filesize < 2MB and all of them
}
