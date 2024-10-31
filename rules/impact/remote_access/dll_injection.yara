rule dll_injection: high {
  meta:
    description = "injects a DLL into other processes"

  strings:
    $prog_rundll          = "rundll32"
    $f_RtlStackDbStackAdd = "RtlStackDbStackAdd"

  condition:
    any of ($prog*) and any of ($f*)
}

rule dll_injection_js: critical {
  meta:
    description = "injects a DLL into other processes from javascript"

  strings:
    $f_child_proc = "require('child_process');"
    $f_fs         = "require('fs');"

  condition:
    filesize < 32KB and dll_injection and any of ($f*)
}
