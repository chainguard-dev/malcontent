rule ld_library_path : notable {
  strings:
	$ref = "LD_LIBRARY_PATH" fullword
  condition:
	any of them
}
