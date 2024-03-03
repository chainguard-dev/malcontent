rule root_path : notable {
	meta:
		description = "References paths within /root"
	strings:
		$root = /\/root\/[%\w\.\-\/]{0,64}/
		$root2 = "/root" fullword
	condition:
		any of them
}