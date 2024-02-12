rule etc_path {
	meta:
		description = "References paths within /etc"
	strings:
		$resolv = /\/etc\/[\w\.\-\/]{0,64}/ 
	condition:
		any of them
}