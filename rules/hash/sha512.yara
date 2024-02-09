rule SHA512 {
  meta:
	description = "Uses the SHA512 signature format"
  strings:
	$ref = "SHA512"
  condition:
	any of them
}
