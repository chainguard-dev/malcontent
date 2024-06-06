rule Office_Document_with_VBA_Project
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature detects an office document with an embedded VBA project. While this is fairly common it is sometimes used for malicious intent."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://msdn.microsoft.com/en-us/library/office/aa201751%28v=office.10%29.aspx"
        labs_reference = "https://labs.inquest.net/dfi/sha256/8a89a5c5dc79d4f8b8dd5007746ae36a3b005d84123b6bbc7c38637f43705023"
        labs_pivot     = "N/A"
        samples        = "8a89a5c5dc79d4f8b8dd5007746ae36a3b005d84123b6bbc7c38637f43705023"

	strings:
			
		$magic1 = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
		$magic2 = /^\x50\x4B\x03\x04\x14\x00\x06\x00/
		$vba_project1 = "VBA_PROJECT" wide nocase
		$vba_project2 = "word/vbaProject.binPK"
	
    condition:
			
		(($magic1 at 0) or ($magic2 at 0)) and any of ($vba_project*)

}