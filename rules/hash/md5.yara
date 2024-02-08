rule MD5 {
  strings:
	$ref = "MD5_"
  condition:
	any of them
}
