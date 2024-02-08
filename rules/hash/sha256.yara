rule SHA256 {
  strings:
	$ref = "SHA256_"
  condition:
	any of them
}
