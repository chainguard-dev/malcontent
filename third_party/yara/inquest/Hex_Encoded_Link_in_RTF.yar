rule Hex_Encoded_Link_in_RTF
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Office documents with a link to download an executable which has been encoded in ASCII hexadecimal form. Malware authors have used this technique to obfuscate malicious payloads."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://isc.sans.edu/diary/Getting+the+EXE+out+of+the+RTF/6703"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "N/A"

	strings:
			
        $m = {7b 5c 72 74 66 31} // RTF
        $a1 = "687474703a2f2f"
        $a2 = "2e657865"
	condition:
			
        $m and all of ($a*)

}