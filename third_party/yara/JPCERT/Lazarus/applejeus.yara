rule AppleJeus_UnionCrypto_code {
     meta:
        description = "UnionCrypto malware in AppleJeus"
        author = "JPCERT/CC Incident Response Group"
        hash = "295c20d0f0a03fd8230098fade0af910b2c56e9e5700d4a3344d10c106a6ae2a"

     strings:
        $http1 = "auth_timestamp:" ascii
        $http2 = "auth_signature:" ascii
        $http3 = "&act=check" ascii
        $http4 = "Windows %d(%d)-%s" ascii
        $key = "vG2eZ1KOeGd2n5fr" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (all of ($http*) or $key)
}

rule AppleJeus_UnionCrypto_loader {
     meta:
        description = "UnionCrypto loader in AppleJeus"
        author = "JPCERT/CC Incident Response Group"
        hash = "949dfcafd43d7b3d59fe3098e46661c883b1136c0836f8f9219552f13607405b"

     strings:
        $xorcode = { 33 D2 4D ?? ?? 01 8B C7 FF C7 F7 F6 42 0F B? ?? ?? 41 3? 4? FF 3B FB }
        $callcode = { 48 8? ?? E8 ?? ?? 00 00 FF D3 4C }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       all of them
}
