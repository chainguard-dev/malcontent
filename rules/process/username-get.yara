rule getlogin {
	meta:
		syscall = "getlogin"
		description = "get login name"
		pledge = "id"
		ref = "https://linux.die.net/man/3/getlogin"
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
		ref = "https://man7.org/linux/man-pages/man1/whoami.1.html"
	strings:
		$ref = "whoami" fullword
	condition:
		any of them
}