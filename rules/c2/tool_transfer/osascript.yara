rule osascript_dropper: high {
  meta:
    description = "osascript dropper"
    filetypes   = "scpt,scptd"

  strings:
    $c_osascript = "osascript" fullword
    $c_tell      = "tell" fullword
    $c_chmod     = "chmod" fullword
    $c_tmp       = "/tmp"

    $perm_x   = "+x" fullword
    $perm_755 = "755" fullword
    $perm_777 = "777" fullword

  condition:
    filesize < 256KB and all of ($c*) and any of ($p*)
}
