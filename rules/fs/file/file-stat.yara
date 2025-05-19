rule stat: harmless {
  meta:
    description = "access filesystem information"
    pledge      = "rpath"
    syscall     = "stat"

  strings:
    $_stat = "_stat"

  condition:
    any of them
}

rule fstat: harmless {
  meta:
    pledge  = "rpath"
    syscall = "fstat"

  strings:
    $ref  = "fstat" fullword
    $ref2 = "fstat64" fullword
    $ref3 = "fstatat64" fullword

  condition:
    any of them
}

rule lstat: harmless {
  meta:
    pledge  = "rpath"
    syscall = "lstat"

  strings:
    $ref  = "lstat" fullword
    $ref2 = "fxstat" fullword

  condition:
    any of them
}

rule go_stat: harmless {
  meta:
    description = "access filesystem information"
    pledge      = "rpath"
    syscall     = "stat"

  strings:
    $filestat  = "os.(*fileStat)"
    $filestat2 = "os.Stat("

  condition:
    any of them
}

rule py_timestamps {
  meta:
    description = "Access filesystem timestamps"
    pledge      = "rpath"
    syscall     = "stat"
    filetypes   = "py"

  strings:
    $atime = "os.path.getatime"
    $mtime = "os.path.getmtime"
    $ctime = "os.path.getctime"

  condition:
    any of them
}

rule npm_stat {
  meta:
    description = "access filesystem metadata"
    pledge      = "rpath"
    syscall     = "stat"
    filetypes   = "js,ts"

  strings:
    $filestat = /fs\.stat[\w\(\'\.\)]{0,32}/

  condition:
    any of them
}

rule file_attributes {
  meta:
    description = "access filesystem attributes"
    pledge      = "rpath"
    syscall     = "stat"

  strings:
    $attr = "fileAttributes"

  condition:
    any of them
}
