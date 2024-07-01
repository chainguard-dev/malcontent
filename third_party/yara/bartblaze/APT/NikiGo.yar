rule NikiGo
{
meta:
	description = "Identifies NikiGo, a Go dropper by (likely) Kimsuky."
	author = "@bartblaze, @nsquar3"
	date = "2024-06"
	tlp = "White"
	hash = "000e2926f6e094d01c64ff972e958cd38590299e9128a766868088aa273599c7"
	reference = "https://cyberarmor.tech/new-north-korean-based-backdoor-packs-a-punch/"

strings:
	$go = "Go build ID:"

	$func1 = "main.ParseCommandLine" ascii wide fullword
	$func2 = "main.RunCmd" ascii wide fullword
	$func3 = "main.HttpGet" ascii wide fullword
	$func4 = "main.SelfDel" ascii wide fullword
	$func5 = "main.RandomBytes" ascii wide fullword

	$pdb_src = "C:/Users/niki/go/src/niki/auxiliary/engine-binder/main.go" ascii wide
	$pdb_path = "/Users/niki/go/src/niki/auxiliary/engine-binder/" ascii wide
	
condition:
	uint16(0) == 0x5A4D and $go and (
	all of ($func*) or
	any of ($pdb*)
	)
}