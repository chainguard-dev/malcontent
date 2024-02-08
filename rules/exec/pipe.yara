rule bsd {
	strings:
		$_popen = "_popen" fullword
		$_pclose = "_pclose" fullword
	condition:
		any of them
}

