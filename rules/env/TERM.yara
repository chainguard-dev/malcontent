rule TERM {
  strings:
	$ref = "TERM" fullword
//	$getenv = "getenv"
  condition:
	all of them
}
