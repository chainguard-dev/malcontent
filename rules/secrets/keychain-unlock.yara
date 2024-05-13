rule keychain_unlcok : high macos {
	meta:
		description = "Unlocks the Keychain"
		ref = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/"
	strings:
		$ref = "KeychainUnlock"
	condition:
		any of them
}
