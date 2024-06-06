rule Suspicious_CLSID_RTF
{
    meta:
        author         = "InQuest Labs"
        description    = "This rule detects RTF documents that have an unusual incidence of hex within the OLECLSID control word."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Internal Research"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "3126f973a80dd2c1cd074f6631d5a36c480b6d5d75d26a02f2f35bc2a62b80f7"

	strings:
			
    $rtf_magic = "{\\rt"  // note that {\rtf1 is not required

    $re1 = /\x7b[^\x7d]{0,10}\\oleclsid[ \t\r\n]+[a-z0-9\x2e\x2d]{0,15}\\\x27[2-7][0-9a-f][a-z0-9\x2e\x2d]{0,15}\\\x27[2-7][0-9a-f][a-z0-9\x2e\x2d]{0,15}\\\x27[2-7][0-9a-f]/ nocase wide ascii
	condition:
			
    $rtf_magic in (0..30) and all of ($re*)


}