rule private_key_val {
  meta:
	description = "References private keys"
  strings:
	$ref = "private_key"
	$ref2 = "PRIVATE_KEY"
	$ref3 = "privateKey"
  condition:
    any of them
}
