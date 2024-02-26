rule dyld_library_path : notable {
  strings:
	$ref = "DYLD_LIBRARY_PATH"
  condition:
	any of them
}
