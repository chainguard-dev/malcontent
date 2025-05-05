rule shell32_ShellExecuteW: high windows {
  meta:
    description = "Runs command using shell32.ShellExecuteW"
    filetypes   = "text/x-python,application/x-python-code"

  strings:
    $shell = "shell32.ShellExecuteW"

  condition:
    filesize < 52428800 and any of them
}
