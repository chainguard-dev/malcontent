rule etc_hosts : notable {
	meta:
		description = "references /etc/hosts"
	strings:
		$ref = "/etc/hosts"
	condition:
		any of them
}