rule TERM : harmless {
  meta:
	description = "Look up or override terminal settings"
  strings:
	$ref = "TERM" fullword
//	$getenv = "getenv"
  condition:
	all of them
}
