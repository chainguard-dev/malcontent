rule SHA1 {
  strings:
	$ref = "SHA1_"
  condition:
	any of them
}
