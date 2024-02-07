rule getmode {
	meta:
		description = "Uses libc functions to access filesystem information"
		pledge = "rpath"
	strings:
		$_chmod = "_getmode"
	condition:
		any of them
}