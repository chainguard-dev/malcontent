rule Microsoft_2007_OLE_Encrypted
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Microsoft OLE documents, version 2007 and above, that are encrypted with a password. An encrypted OLE document alone is not indication of malicious behavior."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://www.iso.org/standard/54796.html"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "64f2c43f3d01eae65125024797d5a40d2fdc9c825c7043f928814b85cd8201a2"

	strings:
		$ole_marker     = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1/

        $enc_marker1    = "EncryptedPackage" nocase ascii wide
        $enc_marker2    = "StrongEncryptionDataSpace" nocase ascii wide
        $enc_marker3    = "<encryption xmlns="
	condition:
			$ole_marker at 0 and all of ($enc_marker*)
}