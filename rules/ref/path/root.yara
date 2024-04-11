rule root_path_val : notable {
	meta:
		description = "References paths within /root"
	strings:
		$root = /\/root\/[%\w\.\-\/]{0,64}/
		$root2 = "/root" fullword

		$not_go_selinux = "SELINUXTYPE"
	condition:
		any of them and none of ($not*)
}