rule root_path : notable {
	meta:
		description = "References paths within /root"
	strings:
		$root = /\/root\/[%\w\.\-\/]{0,64}/
	condition:
		$root
}