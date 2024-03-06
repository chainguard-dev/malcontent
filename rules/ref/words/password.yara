rule password {
	meta:
		description = "References a password"
	strings:
		$ref = "password" fullword
		$ref2 = "Password" fullword
	condition:
		any of them
}