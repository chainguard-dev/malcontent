rule Unk_Mythic_Loader
{
meta:
	id = "14BIyhtqgQCTCfLjhUU27p"
	fingerprint = "v1_sha256_30aabd24914ecbce0404d81427b6c6f2f6c5d92c342070da2cab90ed01bc754b"
	version = "1.0"
	date = "2026-01-27"
	modified = "2026-01-27"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies an unknown loader for Mythic C2, likely redteam or APT."
	category = "MALWARE"
	malware_type = "LOADER"
	hash = "e7e4eee2bed7f472c0cd753f13bee3d2d3eefa7e055374d7fcd89049e836119e"

strings:
	$ = "[-] Error in NTWVM_4"
	$ = "[-] Error in NTWVM_3"
	$ = "[-] Error in NTWVM_2"
	$ = "[-] Error in NTWVM_1"
	$ = "[-] Error in NTAVM: "
	$ = "[-] Unable to get NNSsrc\\syscall.rs"
	$ = "[-] NT headers do not match signature with from dll base"
	$ = "[-] DOS header not matched from base address"
	$ = "[-] Error in NTWVM_4"
	$ = "[-] Unable to get NNS"
	$ = "[+] Found the PEB and the InMemoryOrderModuleList at"
	$ = "[+] Module address:"
	$ = "[+] DOS header matched"
	$ = "[+] NT headers matched"
	$ = "[+] Function name found"
	
condition:
	8 of them
}
