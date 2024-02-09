rule MD5 {
  meta:
	description = "Uses the MD5 signature format"
  strings:
	$ref = "MD5_"
  condition:
	any of them
}
