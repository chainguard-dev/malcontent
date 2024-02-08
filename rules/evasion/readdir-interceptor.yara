
rule ref {
	strings:
		$new65 = "readdir64" fullword
		$old64  = "_readdir64"
		$new32 = "readdir" fullword
		$old32  = "_readdir"
	condition:
		all of them
}
