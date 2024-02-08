rule bsd_libc {
  strings:
	$getenv = "_getenv" fullword
  condition:
	any of them
}
