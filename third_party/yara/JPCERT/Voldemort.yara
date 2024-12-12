rule malware_Voldemort_lnk {
    meta:
        description = "LNK file used to download voldemort malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "c913edc6ea2a6aeb6e963c38bb8b8e1496ac44c5a0663887e3948c9320a8dcfc"

    strings:
        $s1 = "\\python.exe \\\\" ascii wide
        $s2 = "@SSL\\" ascii wide
	    $s3 = {2E 00 70 00 79 00 00 00 08 00 2E 00 5C 00 31 00 2E 00 70 00 64 00 66 00}

    condition:
        (uint32(0) == 0x0000004C) and
        all of them
}

rule malware_Voldemort_python {
    meta:
        description = "Python file used to download voldemort malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "f83cffaa8d6b6288ec88525b51548e76e3d8baa14b61fca3f5015be7d2d31aba"

    strings:
        $s1 = "os.getenv('COMPUTERNAME') + '-' + os.getenv('USERNAME') + '-' + os.getenv('USERDOMAIN') + '-' + str(platform.uname()).lower()" ascii
        $s2 = "if \"windows\" in str(platform.uname()).lower():" ascii
        $s3 = "/stage2-1/' + base64.b64encode(" ascii
        $s4 = "def downloadPNG():" ascii

    condition:
        3 of them
}

rule malware_Voldemort_str {
    meta:
        description = "Voldemort malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "fa383eac2bf9ad3ef889e6118a28aa57a8a8e6b5224ecdf78dcffc5225ee4e1f"

    strings:
        $s1 = "sheets.googleapis.com" wide
        $s2 = "/drive/v3/files/%s?key=%s&alt=media" wide
        $s3 = "/v4/spreadsheets/%s/values/%s!A%d:A%d" wide
        $s4 = "client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token" ascii
        $s5 = "Voldemort_gdrive_c.dll" ascii

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3c)) == 0x00004550 and
        4 of them
}
