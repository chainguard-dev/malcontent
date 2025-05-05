rule registry: medium {
  meta:
    description = "writes to the Windows registry"
    filetypes   = "text/x-python"

  strings:
    $ref  = "winreg"
    $ref2 = "SetValueEx"

  condition:
    all of them
}
