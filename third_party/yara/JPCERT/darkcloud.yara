rule malware_DarkCloud_Stealer_str {
    meta:
        description = "DarkCloud Stealer"
        author = "JPCERT/CC Incident Response Group"
        hash = "a8f6bcae61ed785c8ee0703fb9d3d72b717302c4bc5d651fd2a7aa83b1b696ea"

    strings:
        $vb1 = "__vba" ascii wide
        $vb2 = "VB6.OLB" ascii wide
        $name1 = "DarkCloud Gecko Recovery" ascii wide
        $name2 = "DarkCloud CryptoWallets" ascii wide
        $name3 = "DarkCloud FilesGrabber" ascii wide
        $name4 = "DarkCloud Credentials" ascii wide
        $name5 = "===============DARKCLOUD===============" ascii wide

     condition:
         uint16(0) == 0x5a4d and any of ($vb*) and 3 of ($name*)
}