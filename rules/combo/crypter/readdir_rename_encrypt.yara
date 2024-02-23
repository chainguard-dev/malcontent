
rule conti_alike : suspicious {
	meta:
		description = "Reads directories, renames files, encrypts files"
	strings:
		$readdir = "readdir" fullword
		$rename = "rename" fullword
		$enc1 = "encrypted by"
		$enc2 = "RSA PUBLIC KEY"
		$enc3 = "Encrypting file"
		$enc4 = "files_encrypted"
		$enc5 = "encrypts files"
	condition:
		$readdir and $rename and any of ($enc*)
}
