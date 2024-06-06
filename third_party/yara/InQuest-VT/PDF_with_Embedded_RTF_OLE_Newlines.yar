rule PDF_with_Embedded_RTF_OLE_Newlines
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects suspicious PDF files embedded with RTF files that contain embedded OLE content that injects newlines into embedded OLE contents as a means of payload obfuscation and detection evasion."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Internal Research"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "d784c53b8387f1e2f1bcb56a3604a37b431638642e692540ebeaeee48c1f1a07"

 	strings:
			$rtf_magic = "{\\rt"  // note that {\rtf1 is not required

$rtf_objdata = /\x7b[^\x7d]*\\objdata/ nocase

$nor = "D0CF11E0A1B11AE1" nocase

$obs = /D[ \r\t\n]*0[ \r\t\n]*C[ \r\t\n]*F[ \r\t\n]*1[ \r\t\n]*1[ \r\t\n]*E[ \r\t\n]*0[ \r\t\n]*A[ \r\t\n]*1[ \r\t\n]*B[ \r\t\n]*1[ \r\t\n]*1[ \r\t\n]*A[ \r\t\n]*E[ \r\t\n]*1/ nocase
	condition:
			$rtf_magic and $rtf_objdata and ($obs and not $nor)
}
