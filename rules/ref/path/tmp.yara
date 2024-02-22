rule tmp_path : notable {
	meta:
		description = "References paths within /tmp"
	strings:
		$resolv = /\/tmp\/[%\w\.\-\/]{0,64}/ 
	condition:
		any of them
}