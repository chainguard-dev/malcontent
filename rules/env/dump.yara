rule os_environ : harmless {
  meta:
	description = "Dump values from the environment"
  strings:
	$ref = "os.environ" fullword
  condition:
	any of them
}
