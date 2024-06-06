rule RTF_Header_Obfuscation
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects RTF files that have malformed headers. Threat actors often use such obscure methods to evade detection and deliver malicious payloads."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "f40ff37276a3da414c36789f640e38f3b3b574c6b5811cd3eb55a9cccb3eb9c8"

	strings:
			$bad_header = /^{\\rt[^f]/
	condition:
			$bad_header
}