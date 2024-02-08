
rule _flock {
	strings:
		$_flock = "_flock" fullword
	condition:
		any of them
}
