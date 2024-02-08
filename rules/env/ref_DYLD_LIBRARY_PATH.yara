rule dyld_library_path {
  strings:
	$ref = "DYLD_LIBRARY_PATH"
  condition:
	any of them
}
