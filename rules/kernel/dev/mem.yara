rule mem : suspicious {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "Accesses raw system memory"
	strings:
		$val = "/dev/mem"
	condition:
		any of them
}