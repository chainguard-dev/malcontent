import "pe"

rule Agenda_golang : Go Ransomware
{
	meta:
		version = "1.0"
		first_imported = "2022-09-19"
		last_modified = "2022-09-19"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "https://www.ttc-cert.or.th"
		author = "TTC-CERT"
		description = "Detect Agenda Golang ransomware binary, this YARA rule can extract Go Build ID of the binary file, The Tor Onion URL, and the encrypted file extension used by malware."
		category = "MALWARE"
		malware = "ransomware"
		mitre_att = "T1486"
		hash = "E4A319F7AFAFBBD710FF2DBE8D0883EF332AFCB0363EFD4E919ED3C3FABA0342"
		
	strings:
		$ss1 = /Go build ID: .([a-zA-Z0-9-_\/]{83})./ //Go Build ID of the malware binary
		$ss2 = /Domain: (.*?)\\n/ nocase //Ransomware Onion URL embedded in the malware binary. The Onion URL will be different on disparate targets. 
		$ss3 = /Extension: ([a-zA-Z]{10})/ //Encrypted file extension used by malware binary. The extension will be different on disparate targets.
		$s1 = "enc.exe" ascii wide nocase private
		$s2 = "win-enc/" ascii wide nocase private
		$s3 = "CoreServices" ascii wide nocase private
		$s4 = "ImprovedCryptoService" ascii wide nocase private
		$s5 = "RebootToSafeMode" ascii wide nocase private
		$s6 = "injectIntoAss" ascii wide nocase private
		$s7 = "CopyMeToPublic" ascii wide nocase private
		$s8 = "RemoveShadows" ascii wide nocase private
		$s9 = "ListLocalUsers" ascii wide nocase private
	
	condition:
		uint16(0) == 0x5A4D
		and (filesize >= 5MB and filesize <= 15MB)
		and for any section in pe.sections : ( section.name == ".symtab" )
		and all of ($ss*)
		and 3 of ($s*)
}
