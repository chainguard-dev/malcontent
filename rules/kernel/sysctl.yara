
rule sysctl {
	strings:
		$sysctl = "sysctl"
	condition:
		any of them
}
