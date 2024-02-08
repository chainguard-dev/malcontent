
rule urandom {
	strings:
		$urandom = "/dev/urandom" fullword
	condition:
		any of them
}
