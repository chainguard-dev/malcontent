rule gcc : harmless {
  strings:
	$gcc_except_table = "GCC_except_table"
  condition:
	any of them
}
