

rule DADisk : notable {
	meta:
		description = "Get information about disks"
		ref = "https://developer.apple.com/documentation/diskarbitration"
		platforms = "darwin"
	strings:
		$ref = "DADiskCopyDescription" fullword
		$ref2 = "DADiskCreateFromBSDNAme" fullword
	condition:
		any of them
}
