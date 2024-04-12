rule keychain : notable macos {
	meta:
		description = "May access the macOS keychain"
	strings:
		$ref = "Keychain"
		$ref2 = "keychain"
	condition:
		any of them
}

rule macos_library_keychains : notable {
	meta:
		description = "Accesses the system keychain via files"
	strings:
		$ref = "/Library/Keychains"
	condition:
		any of them
}

rule find_generic_password : suspicious {
  meta:
	description = "Looks up a password from the Keychain"
  strings:
   $ref = /find-generic-passsword[ \-\w\']{0,32}/
   $ctkcard = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
  condition:
    $ref and not $ctkcard
}


rule find_internet_password : suspicious {
  meta:
	description = "Looks up an internet password from the Keychain"
  strings:
    $ref = /find-internet-passsword[ \-\w\']{0,32}/
    $ctkcard = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
  condition:
    $ref and not $ctkcard
}