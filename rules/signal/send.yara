rule bsd_libc {
	strings:
		$kill = "_kill" fullword
	condition:
		any of them
}