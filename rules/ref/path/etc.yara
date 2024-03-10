rule etc_path {
	meta:
		description = "References paths within /etc"
	strings:
		$resolv = /\/etc\/[a-z\.\-\/]{4,32}/ 
	condition:
		any of them
}