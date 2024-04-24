
rule previewers_alike: suspicious {
	meta:
		description = "uploads, accesses a keychain, uses ZIP files"
	strings:
		$upload = "upload"
		$zip = "zip"
		$keychain = "keychain_item"
	condition:
		all of them
}
