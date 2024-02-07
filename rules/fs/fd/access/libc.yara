rule bsd_streams {
	strings:
		$_fclose = "_fclose"
		$_fflush = "_fflush"
		$_fopen = "_fopen"
		$_rewind = "_rewind"
		$_fgetpos = "_fgetpos"
		$_fsetpos = "_fsetposs"
		$_ftell = "_ftell" fullword
		$_ftello = "_ftello" fullword
		$fdopen = "fdopen" fullword
		$freopen = "freopen" fullword
		$fmemopen = "fmemopen" fullword
	condition:
		any of them
}
