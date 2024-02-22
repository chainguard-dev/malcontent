rule USER {
  strings:
	$ref = "USER" fullword
	$getenv = "getenv"
  condition:
	all of them
}
