
rule refs {
	strings:
		$ipify = "api.ipify.org" fullword
	condition:
		any of them
}
