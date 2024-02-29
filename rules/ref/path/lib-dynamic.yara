rule dyntamic_lib : notable {
	meta:
		description = "References a library file that can be generated dynamically"
	strings:
		$ref = "/lib/%s"
	condition:
		$ref
}
