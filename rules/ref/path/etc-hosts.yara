rule etc_hosts : notable {
	meta:
		description = "References /etc/hosts"
	strings:
		$ref = "/etc/hosts"
	condition:
		any of them
}