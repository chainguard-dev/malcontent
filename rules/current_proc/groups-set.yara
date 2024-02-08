rule setgroups {
	meta:
		syscall = "setgroups"
		description = "set group access list"
		pledge = "id"
	strings:
		$ref = "setgroups" fullword
	condition:
		any of them
}