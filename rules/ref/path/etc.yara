rule etc_path {
	meta:
		description = "References paths within /etc"
	strings:
		$resolv = /\/etc\/[a-z\.\-\/]{4,64}/ 
	condition:
		any of them
}