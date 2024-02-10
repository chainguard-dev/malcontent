rule chflags {
	meta:	
		description = "May update file flags using chflags"
	strings:
		$chflags = "chflags" fullword
	condition:
		any of them
}
