rule file_crypter : notable {
	meta:
		description = "Encrypts files"
	strings:
		$ref = "Files encrypted"
		$ref2 = "Encrypting file"
		$ref3 = "encrypts files"
		$ref4 = "files_encrypted"
		$ref5 = "EncryptFile"
		$ref6 = "cryptor" fullword
	condition:
		any of them
}