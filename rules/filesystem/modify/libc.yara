rule mkdir {
	meta:
		description = "Uses libc functions to create directories"
		pledge = "wpath"
	strings:
		$_mkdir = "_mkdir"
	condition:
		any of them
}

rule chmod {
	meta:
		description = "Uses libc functions to change file permissions"
		pledge = "wpath"
	strings:
		$_chmod = "_chmod"
	condition:
		any of them
}

rule setmode {
	meta:
		description = "Uses libc functions to change file permissions"
		pledge = "wpath"
	strings:
		$_setmode = "_setmode"
	condition:
		any of them
}