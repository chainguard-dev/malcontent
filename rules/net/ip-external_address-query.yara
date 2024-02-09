
rule public_ip_api {
	strings:
		$ipify = "api.ipify.org" fullword
	condition:
		any of them
}
