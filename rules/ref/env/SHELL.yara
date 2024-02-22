rule SHELL {
  strings:
	$ref = "SHELL" fullword
//	$getenv = "getenv"
  condition:
	all of them
}
