rule registry: medium {
  meta:
    description = "writes to the Windows registry"
    filetypes   = "py"

  strings:
    $ref  = "winreg"
    $ref2 = "SetValueEx"

  condition:
    all of them
}
