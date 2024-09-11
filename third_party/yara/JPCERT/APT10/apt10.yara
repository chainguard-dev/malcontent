rule APT10_ANEL_InitRoutine {
      meta:
        description = "ANEL malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "2371f5b63b1e44ca52ce8140840f3a8b01b7e3002f0a7f0d61aecf539566e6a1"

    	strings:
    		$GetAddress = { C7 45 ?? ?? 69 72 74 C7 45 ?? 75 61 6C 50 C7 45 ?? 72 6F 74 65 66 C7 45 ?? 63 74 [3-4] C7 45 ?? ?? 65 72 6E C7 45 ?? 65 6C 33 32 C7 45 ?? 2E 64 6C 6C [3-4] FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? }

    	condition:
    		$GetAddress
}

rule APT10_redleaves_strings {
      meta:
        description = "RedLeaves malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "ff0b79ed5ca3a5e1a9dabf8e47b15366c1d0783d0396af2cbba8e253020dbb34"

    	strings:
    		$v1a = "red_autumnal_leaves_dllmain.dll"
        $w1a = "RedLeavesCMDSimulatorMutex" wide

    	condition:
    		$v1a or $w1a
}

rule APT10_redleaves_dropper1 {
      meta:
        description = "RedLeaves dropper"
        author = "JPCERT/CC Incident Response Group"
        hash = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"

     strings:
        $v1a = ".exe"
        $v1b = ".dll"
        $v1c = ".dat"
        $a2a = {E8 ?? ?? FF FF 68 ?? 08 00 00 FF}
        $d2a = {83 C2 02 88 0E 83 FA 08}
        $d2b = {83 C2 02 88 0E 83 FA 10}

     condition:
        all of them
}

rule APT10_redleaves_dropper2 {
      meta:
        description = "RedLeaves dropper"
        author = "JPCERT/CC Incident Response Group"
        hash = "3f5e631dce7f8ea555684079b5d742fcfe29e9a5cea29ec99ecf26abc21ddb74"

     strings:
        $v1a = ".exe"
        $v1b = ".dll"
        $v1c = ".dat"
        $c2a = {B8 CD CC CC CC F7 E1 C1 EA 03}
        $c2b = {68 80 00 00 00 6A 01 6A 01 6A 01 6A 01 6A FF 50}

     condition:
        all of them
}

rule APT10_redleaves_dll {
      meta:
        description = "RedLeaves loader dll"
        author = "JPCERT/CC Incident Response Group"
        hash = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

     strings:
        $a2a = {40 3D ?? ?? 06 00 7C EA 6A 40 68 00 10 00 00 68 ?? ?? 06 00 6A 00 FF 15 ?? ?? ?? ?? 85 C0}

     condition:
        all of them
}

rule APT10_Himawari_strings {
      meta:
        description = "detect Himawari(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "https://www.jpcert.or.jp/present/2018/JSAC2018_01_nakatsuru.pdf"
        hash1 = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

      strings:
        $h1 = "himawariA"
        $h2 = "himawariB"
        $h3 = "HimawariDemo"

      condition: all of them
}

rule APT10_Lavender_strings {
      meta:
        description = "detect Lavender(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"

      strings:
        $a1 = { C7 ?? ?? 4C 41 56 45 }
        $a2 = { C7 ?? ?? 4E 44 45 52 }

      condition: all of them
}

rule APT10_Armadill_strings {
      meta:
        description = "detect Armadill(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"

      strings:
        $a1 = { C7 ?? ?? 41 72 6D 61 }
        $a2 = { C7 ?? ?? 64 69 6C 6C }

      condition: all of them
}

rule APT10_zark20rk_strings {
      meta:
        description = "detect zark20rk(a variant of RedLeaves) in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "d95ad7bbc15fdd112594584d92f0bff2c348f48c748c07930a2c4cc6502cd4b0"

      strings:
        $a1 = { C7 ?? ?? 7A 61 72 6B }
        $a2 = { C7 ?? ?? 32 30 72 6B }

      condition: all of them
}

rule APT10_HTSrl_signed {
      meta:
        description = "HT Srl signature using APT10"
        author = "JPCERT/CC Incident Response Group"
        hash = "2965c1b6ab9d1601752cb4aa26d64a444b0a535b1a190a70d5ce935be3f91699"

    	strings:
            $c="IT"
            $st="Italy"
            $l="Milan"
            $ou="Digital ID Class 3 - Microsoft Software Validation v2"
            $cn="HT Srl"

    	condition:
        	all of them
}

rule APT10_ChChes_lnk {
      meta:
        description = "LNK malware ChChes downloader"
        author = "JPCERT/CC Incident Response Group"
        hash = "6d910cd88c712beac63accbc62d510820f44f630b8281ee8b39382c24c01c5fe"

    	strings:
    		$v1a = "cmd.exe"
     		$v1b = "john-pc"
    		$v1c = "win-hg68mmgacjc"
        $v1d = "t-user-nb"
        $v1e = "C:\\Users\\suzuki\\Documents\\my\\card.rtf" wide

    	condition:
    		$v1a and ($v1b or $v1c or $v1d) or $v1e
}

rule APT10_ChChes_strings
{
      meta:
        description = "ChChes malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "7d515a46a7f4edfbae11837324f7c56b9a8164020e32aaaa3bef7d38763dd82d "

    	strings:
    		$v1a = "/%r.html"
    		$v1b = "http://"
    		$v1c = "atan2"
    		$v1d = "_hypot"
    		$v1e = "_nextafter"
    		$d1a = { 68 04 E1 00 00 }

    	condition:
    		all of them
}

rule APT10_ChChes_powershell {
      meta:
        description = "ChChes dropper PowerShell based PowerSploit"
        author = "JPCERT/CC Incident Response Group"
        hash = "9fbd69da93fbe0e8f57df3161db0b932d01b6593da86222fabef2be31899156d"

    	strings:
    		$v1a = "Invoke-Shellcode"
    		$v1b = "Invoke-shCdpot"
    		$v1c = "invoke-ExEDoc"

    	condition:
    		$v1c and ($v1a or $v1b)
}
