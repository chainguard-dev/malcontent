rule setenv_putenv : harmless {
  strings:
	$setenv = "setenv" fullword
	$putenv = "putenv" fullword
  condition:
	any of them
}
