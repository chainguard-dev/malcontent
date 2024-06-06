rule RTF_Embedded_OLE_Header_Obfuscated
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects suspicious RTF files with embedded OLE documents but the OLE header is obfuscated. This is highly indicative of suspicious behavior done to evade detection"
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://www.anomali.com/blog/analyzing-digital-quartermasters-in-asia-do-chinese-and-indian-apts-have-a-shared-supply-chain"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "c96c560aae3440a7681d24fa53a296c695392ca8edb35043430c383efcd69190"

	strings:
	$rtf_magic = "{\\rt"  // note that {\rtf1 is not required
	
	$obfuscated = /\x7b[^\x7d]*\\object[^\x7d]*\\objemb[^\x7d]*\\objdata[^\x7d]+D[\x09-\x7f]*0[\x09-\x7f]*C[\x09-\x7f]*F[\x09-\x7f]*1[\x09-\x7f]*1[\x09-\x7f]*E[\x09-\x7f]*0[\x09-\x7f]*A[\x09-\x7f]*1[\x09-\x7f]*B[\x09-\x7f]*1[\x09-\x7f]*1[\x09-\x7f]*A[\x09-\x7f]*E[\x09-\x7f]*1/ nocase wide ascii
	
	$normal = /\x7b[^\x7d]*\\object[^\x7d]*\\objemb[^\x7d]*\\objdata[^\x7d]+D0CF11E0A1B11AE1/ nocase wide ascii
	
	condition:
			$rtf_magic in (0..10) and $obfuscated and not $normal
}
