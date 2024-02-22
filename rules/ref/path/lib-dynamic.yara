rule dyntamic_lib : suspicious {
	meta:
		description = "References a library file that can be generated dynamically"
	strings:
		$ref = "/lib/%s"
	condition:
		$ref
}
