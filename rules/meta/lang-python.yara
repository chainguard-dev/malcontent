rule pyinstaller {
  strings:
	$pyinstaller = "Cannot open PyInstaller"
	$py_frozen = "Py_Frozen"
  condition:
	any of them
}
