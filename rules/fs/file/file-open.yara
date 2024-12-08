rule file_open: harmless {
  meta:
    description = "opens files"
    syscall     = "open,close"

  strings:
    $fopen     = "fopen" fullword
    $fopen64   = "fopen64" fullword
    $fclose    = "fclose" fullword
    $file_open = "file open failed"

  condition:
    any of them
}

rule py_open: low {
  meta:
    description = "opens files"
    syscall     = "open,close"

  strings:
    $of = " open("

  condition:
    any of them
}

rule java_open: low {
  meta:
    description = "opens files"
    syscall     = "open,close"

  strings:
    $of  = "openFile"
    $O_F = "OPEN_FILE"

  condition:
    any of them
}
