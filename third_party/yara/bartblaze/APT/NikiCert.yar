import "pe"
rule NikiCert
{
meta:
	description = "Identifies Nexaweb digital certificate used in (likely) Kimsuky campaign."
	author = "@bartblaze, @nsquar3"
	date = "2024-06"
	tlp = "White"
	hash_a = "cca1705d7a85fe45dce9faec5790d498427b3fa8e546d7d7b57f18a925fdfa5d"
	hash_b = "000e2926f6e094d01c64ff972e958cd38590299e9128a766868088aa273599c7"
	reference = "https://cyberarmor.tech/new-north-korean-based-backdoor-packs-a-punch/"

condition:
	uint16(0) == 0x5A4D and
    for any i in (0 .. pe.number_of_signatures) : (
		pe.signatures[i].serial == "03:15:e1:37:a6:e2:d6:58:f0:7a:f4:54:c6:3a:0a:f2"
    )
}