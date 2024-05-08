
rule system_kext_unloader : suspicious {
  strings:
    $kextunload_sys_lib_ext = "kextunload /System/Library/Extensions/"
  condition:
    filesize < 10485760 and any of them
}
