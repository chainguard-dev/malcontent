rule ref {
	strings:
		$ref = "ssh-rsa " fullword
	condition:
		any of them
}


