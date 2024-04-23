rule SHELL {
  meta:
	description = "users preferred SHELL path"
	ref = "https://man.openbsd.org/login.1#ENVIRONMENT"
  strings:
	$ref = "SHELL" fullword
  condition:
	all of them
}
