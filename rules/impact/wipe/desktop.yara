rule USERPROFILE_delete: high {
  meta:
    description = "deletes files in the USERPROFILE directory"
    filetypes   = "py"

  strings:
    $appdata = "USERPROFILE" fullword
    $remove  = /os.remove\([\w\.\(\), ]{0,64}/
    $listdir = /os.listdir\([\w\.\(\), ]{0,64}/

  condition:
    all of them and @remove > @listdir and (@remove - @listdir) < 32
}

rule Desktop_delete: critical {
  meta:
    description = "deletes files in the Desktop directory"
    filetypes   = "py"

  strings:
    $appdata = "USERPROFILE" fullword
    $desktop = "Desktop" fullword
    $remove  = /os.remove\([\w\.\(\), ]{0,64}/
    $listdir = /os.listdir\(.{0,8}[dD]esktop[\w\.\(\), ]{0,64}/

  condition:
    all of them and @remove > @listdir and (@remove - @listdir) < 32
}
