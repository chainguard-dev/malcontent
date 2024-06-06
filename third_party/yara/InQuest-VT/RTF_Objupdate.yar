rule RTF_Objupdate
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects RTF files with an 'objupdate' directive. While not guaranteed to be malicious this signature has proven effective for threat hunting in the field."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://www.biblioscape.com/rtf15_spec.htm"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "eaaefa41eaaeac943dede195f3a00b1e424d152cf08243d023009fafdfa6c52b"

	strings:
			
        $magic1= {7b 5c 72 74 (7B | 66)} // {\rtf{ or {\rt{
        $upd = "\\objupdate" nocase

	condition:
			
        $magic1 in (0..30) and $upd and filesize > 50KB and filesize < 500KB

}