rule malware_spygrace {
     meta:
        description = "SpyGrace"
        author = "JPCERT/CC Incident Response Group"
        hash = "067da693b92b006f0a28b2de103529b5390556b1975f0ef2068c7c7f3ddb1242"

     strings:
        $s1 = "%d%02d%02d-%02d%02d%02d.jpg" ascii wide
        $s2 = "&c007=true" ascii wide
        $s3 = "uid" ascii wide
        $s4 = "Mozilla/5.0" ascii wide
        $s5 = "(10 min)" ascii wide
        $s6 = "\\\\.\\pipe\\async_pipe" ascii wide
        $c1 = {34 ?? [0-3] FE C8 88 02 4? FF C?}
        $c2 = {41 [2-3] C0 E8 02 88 [2-3] 41 [5-6] C0 E1 04 41 [2-3] C0 E8 04 02 C8 88 [2-3] 41 [2-3] 80 E1 0F C0 E1 02 [3] C0 E8 06 02 C8}

     condition:
       uint16(0) == 0x5A4D and 3 of ($s*) and 1 of ($c*)
}


rule malware_spygrace_loader {
     meta:
        description = "SpyGrace Loader"
        author = "JPCERT/CC Incident Response Group"
        hash = "067da693b92b006f0a28b2de103529b5390556b1975f0ef2068c7c7f3ddb1242"

     strings:
        $s1 = "Mozilla/5.0" ascii wide
        $c1 = {66 41 83 34 00 ?? 41 FF C1 49 63 C1 49 83 C0 02 48 3B 42 ??}
        $c2 = {48 0F 47 85 ?? ?? ?? 00 42 0F B7 0C 00 66 41 33 CA 48 8D 85 ?? ?? ?? 00 84 D2}

     condition:
       uint16(0) == 0x5A4D and $s1 and 1 of ($c*)
}
