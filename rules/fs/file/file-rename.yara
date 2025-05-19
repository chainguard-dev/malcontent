rule rename: harmless posix {
  meta:
    syscall = "rename"
    pledge  = "cpath"

  strings:
    $rename   = "rename" fullword
    $renameat = "renameat" fullword

  condition:
    any of them
}

rule explicit_rename: low {
  meta:
    description = "renames files"
    filetypes   = "elf,go,js,macho,m,py,rb,ts"

  strings:
    $rename      = "os.rename" fullword
    $rename_file = "renameFile" fullword
    $move_file   = "MoveFile"
    $ruby        = "File.rename"
    $objc        = "renameFile" fullword
    $go          = "os.Rename" fullword

  condition:
    any of them
}

rule ren: medium windows {
  meta:
    description = "renames files"
    filetypes   = "exe,pe,ps1"

  strings:
    $rename         = "rename"
    $cmd_echo       = "echo off"
    $cmd_powershell = "powershell"

  condition:
    filesize < 16KB and $rename and any of ($cmd*)
}
