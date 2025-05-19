rule elf_processhide: high {
  meta:
    description = "userland rootkit designed to hide processes"
    filetypes   = "elf"

  strings:
    $prochide          = "processhide"
    $process_to_filter = "process_to_filter"

  condition:
    all of them
}

rule process_hider: high {
  meta:
    description = "possible rootkit designed to hide processes"

  strings:
    $hide_process   = "hide_proc" fullword
    $proc_hide      = "proc_hide" fullword
    $process_hide   = "process_hide" fullword
    $process_hiding = "process_hiding" fullword
    $hidden_proc    = "hidden_proc" fullword

  condition:
    filesize < 250KB and any of them
}
