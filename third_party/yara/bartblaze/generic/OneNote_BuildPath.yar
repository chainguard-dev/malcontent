rule OneNote_BuildPath
{
    meta:
        id = "6lPn0V5wZyc2iuEz13uKAZ"
        fingerprint = "f8ed9e3cdd5411e2bda7495c8b00b8e69e8f495db97cf542f6a1f3b790bef7a5"
        version = "1.0"
        first_imported = "2023-02-02"
        last_modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies malicious OneNote file by build path."
        category = "MALWARE"

strings:
	//Z:\build\one\attachment.hta
	$path_0 = {5a003a005c006200750069006c0064005c006f006e0065005c006100740074006100630068006d0065006e0074002e00680074006100}
	//Z:\builder\O P E N.wsf
	$path_1 = {5a003a005c006200750069006c006400650072005c004f00200050002000450020004e002e00770073006600}

condition:
	filesize <200KB and any of them
}
