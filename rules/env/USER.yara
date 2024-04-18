rule USER {
  meta:
    description = "Looks up the USER name of the current user"
  strings:
	$ref = "USER" fullword
	$getenv = "getenv"
  condition:
	all of them
}
