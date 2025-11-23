import "pe"
rule NikiCert
{
    meta:
        id = "64lhugyfG9DlAydhTGBb4F"
        fingerprint = "v1_sha256_d346c46bb51beaefcfdc247e20af3ceda6d239366c7126e1a568036ef4c8f60f"
        version = "1.0"
        creation_date = "2024-06"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze, @nsquar3"
        description = "Identifies Nexaweb digital certificate used in (likely) Kimsuky campaign."
        category = "MALWARE"
        malware = "NIKIHTTP"
        malware_type = "BACKDOOR"
        reference = "https://cyberarmor.tech/new-north-korean-based-backdoor-packs-a-punch/"
        hash = "cca1705d7a85fe45dce9faec5790d498427b3fa8e546d7d7b57f18a925fdfa5d"
        hash = "000e2926f6e094d01c64ff972e958cd38590299e9128a766868088aa273599c7"

condition:
    uint16(0) == 0x5A4D and
    for any i in (0 .. pe.number_of_signatures) : (
        pe.signatures[i].serial == "03:15:e1:37:a6:e2:d6:58:f0:7a:f4:54:c6:3a:0a:f2"
    )
}
