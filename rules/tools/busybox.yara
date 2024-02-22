
rule busybox {
	meta:
		description = "This is a busybox binary"
	strings:
		$ref = "Usage: busybox" fullword
		$ref2 = "BusyBox is copyrighted" fullword
		$re3 = "is a multi-call binary that" fullword
	condition:
		any of them
}
