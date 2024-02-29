rule chmod : notable {
	meta:
		description = "Modifies file permissions using chmod"
		pledge = "fattr"
		syscall = "chmod"
	strings:
		$chmod = "chmod" fullword
		$dotChmod = "Chmod" fullword
		$_setmode = "_setmode" fullword
	condition:
		any of them
}


rule fchmod : notamble {
	meta:
		description = "Modifies file permissions using fchmod"
		pledge = "fattr"
		syscall = "fchmodat"
	strings:
		$fchmod = "fchmod" fullword
		$dotfchmod = ".Fchmod" fullword
		$fchmodat = "fchmodat" fullword
	condition:
		any of them
}

rule chmod_executable_plus : notable {
  meta:
	description = "Makes program an execuatble (plus syntax)"
  strings:
	$ref = /chmod [\-\w ]{0,4}\+[rw]{0,2}x[ \$\w\/\.]{0,64}/
  condition:
	$ref
}

rule chmod_executable_octal : notable {
  meta:
	description = "Makes program an execuatble (octal)"
  strings:
	$ref = /chmod [\-\w ]{0,4}\+[rw]{0,2}[75][ \$\w\/\.]{0,64}/
  condition:
	$ref
}
