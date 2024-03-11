rule getlogin {
	meta:
		syscall = "getlogin"
		description = "get login name"
		pledge = "id"
	strings:
		$ref = "getlogin" fullword
		$ref2 = "getpass.getuser" fullword
	condition:
		any of them
}

rule whoami : notable {
	meta:
		syscall = "getuid"
		description = "returns the user name running this process"
	strings:
		$ref = "whoami" fullword
	condition:
		any of them
}