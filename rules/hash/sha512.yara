rule SHA512 {
  strings:
	$ref = "SHA512"
  condition:
	any of them
}
