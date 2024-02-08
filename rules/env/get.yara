rule bsd_libc : harmless {
  strings:
	$getenv = "getenv" fullword
	$go_Getenv = "Getenv" fullword
  condition:
	any of them
}
