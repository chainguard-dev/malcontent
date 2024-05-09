rule proc_environ : high {
	meta:
		description = "accesses environment variables of other processes"
	strings:
		$string = /\/proc\/[\*%{$][\w\}]{0,12}\/environ/ 
	condition:
		any of them
}
