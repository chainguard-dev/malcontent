import "pe"
rule EE_Dropper
{
    meta:
        id = "25d2Jqee4Uip3sr0muPuRO"
        fingerprint = "v1_sha256_8c095876a8282857f9434e97fce844d79e4dd8994a9dc61d2be3fce8f6dcb6d1"
        version = "1.0"
        date = "2025-10-27"
        modified = "2025-10-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies dropper, EXE dropping and loading 3 CAB files, as seen in Earth Estries campaign."
        category = "MALWARE"
        hash = "3822207529127eb7bdf2abc41073f6bbe4cd6e9b95d78b6d7dd04f42d643d2c3"

	strings:
		$cab = {4D 53 43 46} //MSCF

	condition:
		uint16(0) == 0x5A4D and
		#cab == 3 and
		(
			for any i in (0 .. pe.number_of_resources - 1): (
				pe.resources[i].type_string == "T\x00E\x00S\x00T\x00"
			)
		)
}
