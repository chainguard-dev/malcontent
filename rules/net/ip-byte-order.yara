
rule htonl : notable {
	meta:
		pledge = "inet"
		description = "convert values between host and network byte order"
	strings:
		$ref = "htonl" fullword
		$ref2 = "htons" fullword
	condition:
		any of them in (1300..3000)
}
