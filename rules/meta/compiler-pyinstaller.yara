rule pyinstaller {
  strings:
	$pyinstaller = "Cannot open PyInstaller"
	$onedir = "_PYI_ONEDIR_MODE"
  condition:
	any of them
}
