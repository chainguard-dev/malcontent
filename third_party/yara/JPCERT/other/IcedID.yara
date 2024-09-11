rule malware_IcedID_loader {
     meta:
        description = "IcedID Loader"
        author = "JPCERT/CC Incident Response Group"
        hash = "6ae543b0a3380779b65bff8c3ca0267f741173aed0d35265d6c92c0298fb924c"

     strings:
        $a1 = "update_data.dat" wide
        $a2 = "files/bp.dat" ascii
        $a3 = "Update_%x" wide
        $a4 = "Custom_update" wide
        $b1 = {35 87 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 35 9A 76 00 00}
        $b2 = {C7 ?? ?? C5 9D 1C 81} // FNV1a
        $b3 = {69 ?? ?? 93 01 00 01} // FNV1a

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (all of ($a*) or all of ($b*))
}