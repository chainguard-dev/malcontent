rule Encrypted_Office_Document
{
    meta:
        author         = "InQuest Labs"
		description    = "This signature detects an office document that has been encrypted or password protected. Attackers use the password feature to encrypt files, making it difficult for security products to detect them as malware."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://www.symantec.com/connect/blogs/malicious-password-protected-documents-used-targeted-attacks"
        labs_reference = "https://labs.inquest.net/dfi/sha256/8a89a5c5dc79d4f8b8dd5007746ae36a3b005d84123b6bbc7c38637f43705023"
        labs_pivot     = "N/A"
        samples        = "8a89a5c5dc79d4f8b8dd5007746ae36a3b005d84123b6bbc7c38637f43705023"

	strings:
	    $a = {04 00 00 00 00 00 00 00 01 68 00 00 04 80 00 00 (80|28) 00 00 00 01 00 00 00 ?? ?? ?? ?? 00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 }
        $b = "EncryptedPackage" wide
        $magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
	condition:
	    $a or ($magic in (0..1024) and $b)
}