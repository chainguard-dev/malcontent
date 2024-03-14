rule getmode {
	meta:
		description = "looks up file permissions"
		pledge = "rpath"
	strings:
		$_chmod = "_getmode"
	condition:
		any of them
}