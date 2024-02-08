rule bsd_libc {
  strings:
	$setenv = "_setenv" fullword
	$putenv = "_putenv" fullword
  condition:
	any of them
}
