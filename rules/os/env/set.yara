rule setenv_putenv : harmless {
  meta:
	description = "places a variable into the environment"
  strings:
	$setenv = "setenv" fullword
	$putenv = "putenv" fullword
  condition:
	any of them
}
