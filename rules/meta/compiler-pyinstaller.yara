rule pyinstaller_refs {
  strings:
    $pyinstaller = "Cannot open PyInstaller"
    $onedir      = "_PYI_ONEDIR_MODE"
    $signals     = "pyi-bootloader-ignore-signals"

  condition:
    any of them
}
