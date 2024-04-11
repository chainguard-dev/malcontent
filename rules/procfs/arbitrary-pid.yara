rule proc_arbitrary : notable {
	meta:
		description = "access /proc for arbitrary pids"
	strings:
		$string_val = /\/proc\/[%{$][\/\$\w\}]{0,12}/ 
	condition:
		any of them
}
