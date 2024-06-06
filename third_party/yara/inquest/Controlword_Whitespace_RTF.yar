rule Controlword_Whitespace_RTF
{
    meta:
        author         = "InQuest Labs"
        description    = "This rule detects multiple instances of whitespace characters in the OBJDATA control word in an RTF document."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Internal Research"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "c4754d2d7e02c50de6e0551d6b0567ec3c48d6ae45d9e62ad62d544f66cf131c"

    strings:
		$rtf_magic = "{\\rt"  // note that {\rtf1 is not required

		$re1 = /\x7b[^\x7d]*\\objdata[ \t\r\n]+[a-f0-9\x2e\x2d\r\n\x5c]{0,100}[ \t\r\n]{9,}[a-f0-9\x2e\x2d\r\n\x5c]{0,100}[ \t\r\n]{6,}[a-f0-9\x2e\x2d\r\n\x5c]{0,100}[ \t\r\n]{6}/ nocase wide ascii
		//$re1 is looking within \objdata controll word for at least two instances of whitespace characters (9 or more and 6 or more) in between the contents
	condition:
			
		$rtf_magic in (0..30) and all of ($re*)

}
