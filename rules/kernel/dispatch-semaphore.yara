rule hwloc {
	meta:
		description = "Uses hardware locality (NUMA, etc)"
		ref = "https://linux.die.net/man/7/hwloc"
	strings:
		$ref = "hwloc" fullword
	condition:
		any of them
}
rule dispatch_sem {
	meta:
		description = "Uses Dispatch Semaphores"
		ref = "https://developer.apple.com/documentation/dispatch/dispatch_semaphore"
	strings:
		$ref = "dispatch_semaphore_signal"
	condition:
		any of them
}
