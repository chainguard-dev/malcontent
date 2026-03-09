import "pe"

rule malware_AtlasLoader {
    meta:
        description = "AtlasLoader"
        author = "JPCERT/CC Incident Response Group"
        hash = "11aa581aff8010e4030fdbd3c620d8d75506b1b642393b36a7bddefcbb087e31"
        created_date = "2026-02-09"
        updated_date = "2026-02-09"

    strings:
        $s1 = "RunPluin" ascii
        $s2 = "AtlasPro" wide
        $s3 = "AtlasInfo" ascii
        $s4 = "MainDll.dll" ascii

    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and 
        3 of them
}

rule malware_AtlasPlugin {
    meta:
        description = "AtlasLoader Plugin"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "17452364cdf00c8bdcd9b659253043e37ff76cd044d85d8055b6cc04b2e98302"
        hash2 = "6d5eafc6715f221b8e6e0f81f48a37c214fa4abcc0d7a5c2b15ffcce0309fa62"
        created_date = "2026-03-06"
        updated_date = "2026-03-06"

    strings:
        $s1 = "AtlasPro" wide
        $s2 = "LoginAddress" wide
        $s3 = "LoginPort" wide
        $s4 = "C:\\Users\\xxx85\\Desktop\\atlasPro" ascii
        $s5 = "修改通信加密+加载器\\Release\\Plugin\\x64" ascii wide

    condition:
        pe.exports("RunPluin") and 
        3 of them
}