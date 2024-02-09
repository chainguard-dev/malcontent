rule getenv : harmless {
  meta:
	description = "Retrieve the value of an environment variable"
  strings:
	$getenv = "getenv" fullword
	$go_Getenv = "Getenv" fullword
  condition:
	any of them
}
