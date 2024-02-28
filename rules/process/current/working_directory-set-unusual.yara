rule unusual_cd : suspicious {
	meta:
		description = "changes to an unusual directory"
	strings:
		$ref1 = "cd /var/run"
		$ref2 = "cd /var/tmp"
		$ref3 = "cd /dev"
		$ref4 = "cd /mnt"
		$ref5 = "cd /root"
		$ref6 = "cd /usr"
	condition:
		any of them
}
