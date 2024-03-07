rule lockedFiles : suspicious {
	meta:
		description = "References 'locked files'"
	strings:
		$ref = "lockedFiles"
		$ref2 = "lockedFileNames"
	condition:
		any of them
}