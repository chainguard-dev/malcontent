rule system_kext_unloader: high {
  meta:
    description = "unloads system kernel extensions"

  strings:
    $kextunload_sys_lib_ext = "kextunload /System/Library/Extensions/"

  condition:
    filesize < 10485760 and any of them
}
