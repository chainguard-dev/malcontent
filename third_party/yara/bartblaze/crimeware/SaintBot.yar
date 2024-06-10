rule SaintBot
{
    meta:
        id = "5zQ5DvA1lpgHKfGgGgFvvp"
        fingerprint = "f8ed9e3cdd5411e2bda7495c8b00b8e69e8f495db97cf542f6a1f3b790bef7a5"
        version = "1.0"
        creation_date = "2022-07-29"
        first_imported = "2022-07-29"
        last_modified = "2022-07-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Saint Bot malware downloader."
        category = "MALWARE"
        malware = "SAINTBOT"
        malware_type = "DOWNLOADER"

    strings:
        $ = "de:regsvr32" ascii wide
        $ = "de:LoadMemory" ascii wide
        $ = "de:LL" ascii wide
        $ = "/gate.php" ascii wide

    condition:
        all of them
}
