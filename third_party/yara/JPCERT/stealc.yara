rule malware_Stealc_str {
    meta:
        description = "Stealc infostealer"
        author = "JPCERT/CC Incident Response Group"
        hash = "c9bcdc77108fd94f32851543d38be6982f3bb611c3a1115fc90013f965ed0b66"

    strings:
        $decode_code = {
          68 D0 07 00 00
          6A 00
          8D 85 ?? ?? ?? ??
          50
          FF 15 ?? ?? ?? ??
          83 C4 0C
          C7 85 ?? ?? ?? ?? 00 00 00 00
          EB ??
          8B 8D ?? ?? ?? ??
          83 C1 01
          89 8D ?? ?? ?? ??
          81 BD ?? ?? ?? ?? 00 01 00 00
        }
        $anti_code1 = {6A 04 68 00 30 00 00 68 C0 41 C8 17 6A 00 FF 15}
        $anti_code2 = {90 8A C0 68 C0 9E E6 05 8B 45 ?? 50 E8}
        $s1 = "- IP: IP?" ascii
        $s2 = "- Country: ISO?" ascii
        $s3 = "- Display Resolution:" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       ($decode_code or all of ($anti_code*) or all of ($s*))
}