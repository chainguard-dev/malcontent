rule Microsoft_LNK_with_CMD_EXE_Reference
{
    meta:
        Author = "InQuest Labs"
        Description = "This rule detects Microsoft Windows LNK shortcut files that reference the cmd.exe command interpreter. While not necessarily indicative of malicious behavior, this is a common pivot leveraged by a variety of malware campaigns."
        Creation_Date = "2017-11-22"
        Updated_Date = "2022-06-17"
        blog_reference = "N/A"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "15651b4516dc207148ad6d2cf098edc766dc06fc26c79d498305ddcb7c930eab"
    strings:
    $c1 = "\\Windows\\System32\\cmd.exe" nocase ascii wide

    $s1 = /cmd.exe[ \t]+\x2f[a-z][ \t]/ ascii wide nocase
    $s2 = { 00 25 00 53 00 79 00 73 00 74 00 65 00 6D 00 52
    00 6F 00 6F 00 74 00 25 00 5C 00 53 00 79 00 73
    00 74 00 65 00 6D 00 33 00 32 00 EF 01 2F 00 43
    00 20 00 22 00 63 00 6D 00 64 00 2E 00 65 00 78
    00 65 }
    $s3 = "%comspec%" ascii wide nocase fullword

    condition:
            ( uint32(0) == 0x0000004c and filesize < 4KB and $c1 and 1 of ($s*) )
}
