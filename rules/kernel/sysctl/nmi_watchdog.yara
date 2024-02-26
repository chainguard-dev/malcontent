
rule nmi_watchdog : suspicious {
	meta:
		description = "accesses kern.nmi_watchdog control"
	strings:
		$ref = "nmi_watchdog"
	condition:
		any of them
}


rule nmi_watchdog_disable : suspicious {
	meta:
		description = "disables kern.nmi_watchdog - possible miner"
	strings:
		$ref = "nmi_watchdog=0"
	condition:
		any of them
}