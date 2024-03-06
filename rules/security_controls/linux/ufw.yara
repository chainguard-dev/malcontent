rule ufw : notable {
	meta:
		description = "interacts with the ufw firewall"
	strings:
		$ref = "ufw" fullword
	condition:
		any of them
}
