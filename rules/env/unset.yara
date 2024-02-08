rule bsd_libc : harmless {
  strings:
	$ref = "unsetenv" fullword
  condition:
	any of them
}
