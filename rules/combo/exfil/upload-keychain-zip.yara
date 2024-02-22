
rule previewers_alike: suspicious {
	meta:
		description = "Uploads, accesses a keychain, uses ZIP files"
	strings:
		$upload = "upload"
		$zip = "zip"
		$keychain = "keychain_item"
	condition:
		all of them
}
