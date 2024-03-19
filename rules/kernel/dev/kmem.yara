
rule kmem : suspicious {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "Accesses raw kernel memory"
	strings:
		$val = "/dev/kmem"
	condition:
		any of them
}
