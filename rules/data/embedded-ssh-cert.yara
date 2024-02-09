rule ssh_cert {
	strings:
		$rsa = "ssh-rsa " fullword
		$dsa = "ssh-dsa " fullword
	condition:
		any of them
}


