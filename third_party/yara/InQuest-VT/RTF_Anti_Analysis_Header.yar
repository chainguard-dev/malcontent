rule RTF_Anti_Analysis_Header
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects strings found in malicious RTF documents"
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://decalage.info/rtf_tricks"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "08d7cef89f944e90fa8afb2114cd31dea1dd8de7f144ddccb6ce590c0738ffc5"

	strings:
			
		$r1 = /[\x0d\x0aa-f0-9\s]{64}(\{\\object\}|\\bin)[\x0d\x0aa-f0-9\s]{64}/ nocase
	condition:
			
		uint32(0) == 0x74725C7B and (not uint8(4) == 0x66 or $r1)

}