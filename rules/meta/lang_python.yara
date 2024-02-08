rule pyinstaller {
  strings:
	$pyinstaller = "Cannot open PyInstaller"
  condition:
	any of them
}
