rule bsd_libc : harmless {
  strings:
	$getenv = "getenv" fullword
  condition:
	any of them
}
