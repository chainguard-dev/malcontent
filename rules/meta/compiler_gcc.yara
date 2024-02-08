rule gcc {
  strings:
	$gcc_except_table = "GCC_except_table"
  condition:
	any of them
}
