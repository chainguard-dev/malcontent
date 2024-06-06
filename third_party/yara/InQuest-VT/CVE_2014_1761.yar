rule CVE_2014_1761
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects a specially crafted RTF file that is designed to trigger a memory corruption vulnerability in the RTF parsing code that would allow an attacker to execute arbitrary code. The successful exploitation of this vulnerability gains the same user rights as the current user."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://technet.microsoft.com/en-us/security/advisory/2953095"
        labs_reference = "N/A"
        labs_pivot     = "https://labs.inquest.net/dfi/sha256/db0037a9753c364022af4bb7d578996b78ccc3c28b01c6632ccd95a69d49d67c"
        samples        = "db0037a9753c364022af4bb7d578996b78ccc3c28b01c6632ccd95a69d49d67c"

	strings:
			
		$magic = { 7B 5C 72 74 }
		$author = { 5C 61 75 74 68 6F 72 20 69 73 6D 61 69 6C 20 2D 20 5B 32 30 31 30 5D } /* \author ismail - [2010] */
		$operator = { 5C 6F 70 65 72 61 74 6F 72 20 69 73 6D 61 69 6C 20 2D 20 5B 32 30 31 30 5D } /* \operator ismail - [2010] */
	condition:
			
		$magic at 0 and $author or $operator in (0..1024)

}