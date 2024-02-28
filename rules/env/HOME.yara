rule HOME {
  meta:
    description = "Looks up the HOME directory for the current user"
  strings:
	$ref = "HOME" fullword
	$getenv = "getenv"
  condition:
	all of them
}
