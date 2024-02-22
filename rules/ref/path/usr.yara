rule usr_path {
	meta:
		description = "References paths within /usr/"
	strings:
		$resolv = /\/usr\/[\w\.\-\/]{0,64}/ 
	condition:
		any of them
}