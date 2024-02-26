rule HOME {
  strings:
	$ref = "HOME" fullword
	$getenv = "getenv"
  condition:
	all of them
}
