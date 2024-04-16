rule firefox_master_password : suspicious {
	meta:
		description = "Decrypts Firefox master password"
	strings:
		$firefox = "Firefox"
		$nssPrivate = "nssPrivate"
	condition:
		all of them
}
