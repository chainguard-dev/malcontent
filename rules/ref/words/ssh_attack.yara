rule ssh_attack : high {
	meta:
		description = "references an 'SSH Attack'"
	strings:
		$ref = /[a-zA-Z\-_ ]{0,16}sshAttack[a-zA-Z\-_ ]{0,16}/ fullword
		$ref2 = /[a-zA-Z\-_ ]{0,16}ssh_attack[a-zA-Z\-_ ]{0,16}/ fullword
		$ref3 = /[a-zA-Z\-_ ]{0,16}attackSSH[a-zA-Z\-_ ]{0,16}/ fullword
		$ref4 = /[a-zA-Z\-_ ]{0,16}attackSsh[a-zA-Z\-_ ]{0,16}/ fullword
		$ref5 = /[a-zA-Z\-_ ]{0,16}attack_ssh[a-zA-Z\-_ ]{0,16}/ fullword
		$ref2 = /[a-zA-Z\-_ ]{0,16}ssh_boom[a-zA-Z\-_ ]{0,16}/ fullword
	condition:
		any of them
}