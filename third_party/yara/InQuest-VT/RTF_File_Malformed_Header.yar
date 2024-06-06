rule RTF_File_Malformed_Header
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects compound RTF documents with malformed headers which is typically an indication of attackers trying to evade detection."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "e3b5cf3c05d824634d2748fac40216275e7f9f47c94dfa4dfa89f976841698bd"

	strings:
        $rtf_header1 = /^.{0,10}{\\rtf[a-z0-9\x5c]+[@='"\x2f()~!#$%^&*_+=|;:,<.>?\x80-\xff\x2d\x5b\x5d\x60]+[a-z0-9]+[@='"\x2f()~!#$%^&*_+=|;:,<.>?\x80-\xff\x2d\x5b\x5d\x60]+[a-z0-9]+[@='"\x2f()~!#$%^&*_+=|;:,<.>?\x80-\xff\x2d\x5b\x5d\x60]/ nocase

        $rtf_header2 = /^.{0,10}{\\rtf[a-z0-9]+[^\{\}\x0d\x0a]{100,}/ nocase  // note that {\rtf1 is not required
	condition:
			all of ($rtf_header*)
}