
rule sysctl : harmless {
	strings:
		$sysctl = "sysctl"
		$Sysctl = "Sysctl"
	condition:
		any of them
}
