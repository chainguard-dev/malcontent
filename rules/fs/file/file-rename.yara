rule rename: harmless posix {
  meta:
    syscall = "rename"
    pledge  = "cpath"

  strings:
    $rename      = "rename" fullword
    $renameat    = "renameat" fullword
    $rename_file = "renameFile" fullword
    $move_file   = "MoveFile"
    $ruby        = "File.rename"

  condition:
    any of them
}

rule os_rename: low {
  meta:
    description = "renames files"
    filetypes   = "py"

  strings:
    $rename = "os.rename" fullword

  condition:
    any of them
}

rule ren: medium windows {
  meta:
    description = "renames files"

  strings:
    $del            = "rename" fullword
    $cmd_echo       = "echo off"
    $cmd_powershell = "powershell"

  condition:
    filesize < 16KB and $del and any of ($cmd*)
}
