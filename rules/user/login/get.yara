rule getlogin : harmless {
	meta:
		syscall = "getlogin"
		description = "get login name"
		pledge = "id"
	strings:
		$ref = "getlogin" fullword
	condition:
		any of them
}