rule etc_path {
	strings:
		$resolv = /\/etc\/(\w\.\-)*/ 
	condition:
		any of them
}