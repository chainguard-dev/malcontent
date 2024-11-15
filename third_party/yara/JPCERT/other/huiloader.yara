rule malware_HUILoader_code {
    meta:
        description = "detect HUI Loader code"
        author = "JPCERT/CC Incident Response Group"



    strings:
        $push1 = { (B9|68) F4 01 00 00 FF }
        $push2 = { (B9|68) E8 03 00 00 FF }
        $xor1 = { 80 F3 20 }
        $xor2 = { 80 30 20 }
        $xor3 = { 80 34 30 20 }
        $add = { 83 C? 32 }
        $fui = "HUIHWASDIHWEIUDHDSFSFEFWEFEWFDSGEFERWGWEEFWFWEWD" ascii wide

    condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       filesize < 200KB and
       (
          $fui or
          (all of ($push*) and #add == 2 and 1 of ($xor*))
       )
}
