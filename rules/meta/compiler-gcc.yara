rule gcc : harmless {
  strings:
	$gcc_except_table = "GCC_except_table"
	$gcc_version = "GCC: "
  condition:
	any of them
}
