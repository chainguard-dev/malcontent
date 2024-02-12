rule etc_hosts : suspicious {
	meta:
		description = "References /etc/hosts"
	strings:
		$ref = "/etc/hosts"
	condition:
		any of them
}