rule USER {
  meta:
    description = "Looks up the USER name of the current user"
	ref = "https://man.openbsd.org/login.1#ENVIRONMENT"
  strings:
	$ref = "USER" fullword
	$getenv = "getenv"
  condition:
	all of them
}
