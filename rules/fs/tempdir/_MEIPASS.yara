rule sys_MEIPASS: low {
  meta:
    description = "references PyInstaller bundle folder"

  strings:
    $ref = "sys._MEIPASS"

  condition:
    any of them
}
