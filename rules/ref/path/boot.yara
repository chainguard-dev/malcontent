rule boot_path : notable {
	meta:
		description = "References paths within /boot"
	strings:
		$ref = /\/boot\/[\%\w\.\-\/]{4,32}/ fullword
	condition:
		$ref
}

rule elf_boot_path : suspicious {
	meta:
		description = "References paths within /boot"
	strings:
		$ref = /\/boot\/[\%\w\.\-\/]{4,32}/ fullword
	condition:
		uint32(0) == 1179403647 and $ref
}