rule SHELL {
  meta:
	description = "users preferred SHELL path"
  strings:
	$ref = "SHELL" fullword
//	$getenv = "getenv"
  condition:
	all of them
}
