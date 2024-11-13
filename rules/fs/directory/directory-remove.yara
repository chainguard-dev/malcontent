rule rmdir {
  meta:
    description = "Uses libc functions to remove directories"
    pledge      = "wpath"

  strings:
    $rmdir           = "rmdir" fullword
    $Rmdir           = "Rmdir" fullword
    $removeDirectory = "removeDirectory" fullword

  condition:
    any of them
}
