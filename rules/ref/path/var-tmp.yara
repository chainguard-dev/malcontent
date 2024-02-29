rule var_tmp_path : notable {
	meta:
		description = "References paths within /var/tmp"
	strings:
		$resolv = /var\/tmp\/[%\w\.\-\/]{0,64}/ 
	condition:
		any of them
}