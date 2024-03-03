rule var_log_path : notable {
	meta:
		description = "references paths within /var/log"
	strings:
		$ref = /\/var\/log\/[\%\w\.\-\/]{4,32}/ fullword
	condition:
		$ref
}

rule elf_var_log_path : suspicious {
	meta:
		description = "references paths within /var/log"
	strings:
		$ref = /\/var\/log\/[\%\w\.\-\/]{4,32}/ fullword
	condition:
		uint32(0) == 1179403647 and $ref
}