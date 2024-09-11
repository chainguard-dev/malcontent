import "pe"

rule malware_webrcs_lnk {
    meta:
        description = "lnk used to execute webrcs"
        author = "JPCERT/CC Incident Response Group"
        hash = "405b2933f2638767980171f3cb09e3f3ee598965d74dd5a041cac97e4e1b893d"

    strings:
        $s1 = "'+$pid+'.dll';ni " ascii wide
        $s2 = "-I D;saps $f;cp desktop.ini " ascii wide
        $s3 = ";if(Test-Path $n){saps $" ascii wide

    condition:
        (uint32(0) == 0x0000004C) and
        2 of them
}

rule malware_webrcs {
    meta:
        description = "webrcs malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "74aa2eedaa6594efa2075ea2f4617ed3206d228b8fae5fc54382630764bdb5ad"

    strings:
        $s1 = "C:\\boringssl_x86\\ssl\\encrypted_client_hello.cc" ascii 
        $s2 = "_rloader@4" ascii
        $s3 = "shell" wide
        $s4 = {
			83 3A 10
			0F 85 ?? ?? ?? ??
			83 39 0F
			75 ??
			83 38 0F
			75 ??
			83 78 ?? 41
		}
        $s5 = "cqWKroElukZpUd7X2FRJhAC3IS05j6efzDmaVwv4igGtTY89sOx1QHPNBMLybn+-" ascii

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3c)) == 0x00004550 and
        (pe.overlay.size > 512000 and
        uint8(pe.overlay.offset) == 0xBF and
        uint32(pe.overlay.offset + 4) == 0x09E8006A) or
        3 of them
}