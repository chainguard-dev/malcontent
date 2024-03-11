rule setlogin : notable {
	meta:
		syscall = "setlogin"
		description = "set login name"
		pledge = "id"
	strings:
		$ref = "setlogin" fullword
	condition:
		any of them
}