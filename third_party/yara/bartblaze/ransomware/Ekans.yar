rule Ekans
{
    meta:
        id = "6Kzy2bA2Zj7kvpXriuZ14m"
        fingerprint = "396b915c02a14aa809060946c9294f487a5107ab37ebefb6d5cde07de4113d43"
        version = "1.0"
        creation_date = "2020-03-01"
        first_imported = "2021-12-30"
        last_modified = "2023-12-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Ekans aka Snake ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "EKANS"
        malware_type = "RANSOMWARE"

    strings:
        $ = "already encrypted!" ascii wide
        $ = "error encrypting %v : %v" ascii wide
        $ = "faild to get process list" ascii wide
        $ = "There can be only one" ascii wide fullword
        $ = "total lengt: %v" ascii wide fullword

    condition:
        3 of them
}
