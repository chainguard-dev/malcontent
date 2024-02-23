rule ransomware_mention : suspicious {
	meta:
		description = "Mentions ransomware"
	strings:
		$ransomware = "ransomware"
		$locker = "locker encrypt"
	condition:
		any of them
}