rule private_key {
  meta:
	ref = "References private keys"
  strings:
	$ref = "private_key"
	$ref2 = "PRIVATE_KEY"
	$ref3 = "privateKey"
  condition:
    any of them
}
