rule bsd_libc {
	strings:
		$_fork = "_fork" fullword
	condition:
		any of them
}

