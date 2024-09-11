rule malware_donut_shellcode {
     meta:
        description = "donut shellcode"
        author = "JPCERT/CC Incident Response Group"
        hash = "d7969f7f5bf0ffe5bf83e642e056417cc5c4b54a7b99121466bf1427f71d62c3"
        reference = "https://github.com/TheWover/donut"

     strings:
       $code = { 59 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 81 EC 00 05 00 00 }

     condition:
       all of them and
       ((uint8(0) == 0x90 and
         uint32(2) == uint32(6) and
         uint32(uint32(6) + 6) == 0x5C894859)
        or
        (uint8(0) == 0xE8 and
         uint32(1) == uint32(5) and
         uint32(uint32(5) + 5) == 0x5C894859))
}