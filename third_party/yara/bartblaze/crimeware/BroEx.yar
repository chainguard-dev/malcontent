rule BroEx
{
meta:
	id = "5MNXppaMBFMS0DMQ63eCJO"
	fingerprint = "8eea2d3d8d4e8ca6ef89d474232d1117e2a5a5b4c714b4c82493293f31e4f2c6"
	version = "1.0"
	first_imported = "2023-09-18"
	last_modified = "2023-09-18"
	status = "RELEASED"
	sharing = "TLP:WHITE"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Detects BroEx, a type of agressive adware."
	category = "MALWARE"
	malware = "BROEX"
	malware_type = "ADWARE"
	hash = "7f103012a143b9e358087cf94dbdd160362a57e5ebc65c560e352ac7541bd80e"

strings:
	//PDB
	$pdb = "I:\\Repository2\\test\\Project21\\event\\Release\\event.pdb" ascii wide
	
	//Mutants
	$mut1 = "Global\\A6A161D8-150E-46A1-B7EC-18E4CB58C6D2" ascii wide
	$mut2 = "Global\\D80D9D78-BCDA-482C-98F2-C38991A8CA3" ascii wide
	$mut3 = "Global\\8D13D07B-A758-456A-A215-0518F1268C2A" ascii wide
	
	//Launch
	$browser1 = "main -c rbrowser chrome" ascii wide
	$browser2 = "main -c rbrowser msedge" ascii wide
	
	//Service names
	$svc1 = "WimsysUpdaterService" ascii wide
	$svc2 = "WimsysService" ascii wide
	$svc3 = "WimsysServiceX64" ascii wide
	
	/*
	pvVar1 = (void *)0x0;
	param_1[3] = (void *)0x7;
	param_1[2] = (void *)0x0;
	*(undefined2 *)param_1 = 0;
	if (*(short *)param_2 != 0) {
	pvVar1 = (void *)0xffffffffffffffff;
	*/
	$str_decode = { 4? 53 4? 83 ec 20 4? 33 c0 4? c7 41 18 07 00 00 00 4? 8b d9 4? 89 41 10 66 4? 89 01 66 4? 39 02 74 11 4? 83 c8 ff  }

condition:
	uint16(0) == 0x5a4d and ($pdb or 2 of ($mut*) or all of ($browser*) 
	or 2 of ($svc*) or $str_decode)
}
