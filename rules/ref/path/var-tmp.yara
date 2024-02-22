rule var_tmp_path : suspicious {
	meta:
		description = "References paths within /var/tmp"
	strings:
		$resolv = /var\/tmp\/[%\w\.\-\/]{0,64}/ 
	condition:
		any of them
}