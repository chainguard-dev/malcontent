rule kcore : unusual {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "Accesses the physical memory of the system in core file format"
	strings:
		$ref = "/proc/kcore"
	condition:
		any of them
}


rule kmem : unusual {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "Accesses raw kernel memory"
	strings:
		$ref = "/dev/kmem"
	condition:
		any of them
}

rule mem : unusual {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "Accesses raw system memory"
	strings:
		$ref = "/dev/mem"
	condition:
		any of them
}