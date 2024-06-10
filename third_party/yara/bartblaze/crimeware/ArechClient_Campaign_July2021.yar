import "dotnet"

rule ArechClient_Campaign_July2021
{
    meta:
        id = "16N9HHtspErd7pE2A261Mh"
        fingerprint = "971fcef8b604c185c14af001633a3f83297d183f47620a9c4fc014815b26a28f"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ArechClient stealer's July 2021 campaign."
        category = "MALWARE"
        malware = "ARECHCLIENT"
        malware_type = "INFOSTEALER"
        reference = "https://twitter.com/bcrypt/status/1420471176137113601"


    condition:
        dotnet.guids[0]=="10867a7d-8f80-4d52-8c58-47f5626e7d52" or dotnet.guids[0]=="7596afea-18b9-41f9-91dd-bee131501b08"
}