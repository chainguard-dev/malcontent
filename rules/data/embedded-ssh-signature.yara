rule ssh_signature {
	meta:
		description = "Contains embedded SSH signature"
	strings:
		$sig = "--BEGIN SSH SIGNATURE--"
	condition:
		any of them
}


