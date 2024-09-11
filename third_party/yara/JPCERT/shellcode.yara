rule malware_shellcode_hash {
    meta:
        description = "detect shellcode api hash value"
        author = "JPCERT/CC Incident Response Group"
        ref = "https://github.com/fireeye/flare-ida/blob/master/shellcode_hashes/sc_hashes.db"

    strings:
        $addRol5HashOncemore32_GetProcAddress = { 67 42 56 25 }
        $addRol5HashOncemore32_LoadLibraryA = { CC 70 77 6B }
        $imul21hAddHash32_GetProcAddress = { BF C1 CF DE }
        $imul21hAddHash32_LoadLibraryA = { DB 2F 07 B7 }
        $ror7AddHash32_GetProcAddress = { 85 DF AF BB }
        $ror7AddHash32_LoadLibraryA = { 32 74 91 0C }
        $shl7SubHash32DoublePulser_GetProcAddress = { B8 F8 FD 0A }
        $shl7SubHash32DoublePulser_LoadLibraryA = { 54 BE 48 01 }
        $imul83hAdd_GetProcAddress = { 54 B8 B9 1A }
        $imul83hAdd_LoadLibraryA = { 78 1F 20 7F }
        $xorShr8Hash32_GetProcAddress = { E5 52 D8 8D }
        $xorShr8Hash32_LoadLibraryA = { 31 7E EE 06 }
        $or23hXorRor17Hash32_GetProcAddress = { 33 00 A1 98 }
        $or23hXorRor17Hash32_LoadLibraryA = { 1F 0C B9 8E }
        $shl7Shr19XorHash32_GetProcAddress = { C8 FA C8 1B }
        $shl7Shr19XorHash32_LoadLibraryA = { 07 90 E4 63 }
        $rol3XorHash32_GetProcAddress = { 84 9B 50 F2 }
        $rol3XorHash32_LoadLibraryA = { 89 FD 12 A4 }
        $ror13AddHash32Sub20h_GetProcAddress = { 7A EE CA 1A }
        $ror13AddHash32Sub20h_LoadLibraryA = { 76 46 8B 8A }
        $crc32_GetProcAddress = { FF 1F 7C C9 }
        $crc32_LoadLibraryA = { 8D BD C1 3F }
        $chAddRol8Hash32_GetProcAddress = { 11 78 32 28 }
        $chAddRol8Hash32_LoadLibraryA = { 41 5F 59 35 }
        $ror13AddHash32Dll_GetProcAddress = { 49 F7 02 78 }
        $ror13AddHash32Dll_LoadLibraryA = { 4C 77 26 07 }
        $playWith0xedb88320Hash_GetProcAddress = { FF 1F 7C C9 }
        $playWith0xedb88320Hash_LoadLibraryA = { 8D BD C1 3F }
        $rol9AddHash32_GetProcAddress = { 89 2F AC 6B }
        $rol9AddHash32_LoadLibraryA = { EB 9F D7 E0 }
        $crc32_bzip2_GetProcAddress = { 92 A8 C4 0D }
        $crc32_bzip2_LoadLibraryA = { CB 8C AA 7A }
        $ror9AddHash32_GetProcAddress = { 8E 9F 45 72 }
        $ror9AddHash32_LoadLibraryA = { CA CC DE 43 }
        $ror11AddHash32_GetProcAddress = { D0 05 89 E9 }
        $ror11AddHash32_LoadLibraryA = { 97 16 5F FA }
        $rol7AddHash32_GetProcAddress = { 54 15 7F FC }
        $rol7AddHash32_LoadLibraryA = { C9 FF DF 10 }
        $ror13AddHash32_GetProcAddress = { AA FC 0D 7C }
        $ror13AddHash32_LoadLibraryA = { 8E 4E 0E EC }
        $ror13AddHash32Sub1_GetProcAddress = { A9 FC 0D 7C }
        $ror13AddHash32Sub1_LoadLibraryA = { 8D 4E 0E EC }
        $rol3XorEax_GetProcAddress = { 08 EE 31 9C }
        $rol3XorEax_LoadLibraryA = { FB 32 8C AE }
        $xorRol9Hash32_GetProcAddress = { 93 40 B9 B4 }
        $xorRol9Hash32_LoadLibraryA = { 5E 4B A6 8D }
        $rol9XorHash32_GetProcAddress = { A0 5C DA 49 }
        $rol9XorHash32_LoadLibraryA = { 25 D3 46 AF }
        $rol5AddHash32_GetProcAddress = { 90 55 C9 99 }
        $rol5AddHash32_LoadLibraryA = { DC DD 1A 33 }
        $poisonIvyHash_GetProcAddress = { 1F 7C C9 FF }
        $poisonIvyHash_LoadLibraryA = { AD D1 34 41 }
        $rol7XorHash32_GetProcAddress = { EE EA C0 1F }
        $rol7XorHash32_LoadLibraryA = { 26 80 AC C8 }
        $crc32Xor0xca9d4d4e_GetProcAddress = { B1 52 E1 03 }
        $crc32Xor0xca9d4d4e_LoadLibraryA = { C3 F0 5C F5 }
        $playWith0xe8677835Hash_GetProcAddress = { 54 EF 20 A1 }
        $playWith0xe8677835Hash_LoadLibraryA = { D1 18 AC A7 }
        $addRor13HashOncemore32_GetProcAddress = { 9F 2A 7F 03 }
        $addRor13HashOncemore32_LoadLibraryA = { BB A3 93 03 }
        $shl7Shr19AddHash32_GetProcAddress = { 54 15 7F FC }
        $shl7Shr19AddHash32_LoadLibraryA = { C9 FF DF 10 }
        $or21hXorRor11Hash32_GetProcAddress = { 77 CD 66 33 }
        $or21hXorRor11Hash32_LoadLibraryA = { 92 7C D0 94 }
        $or60hAddShl1Hash32_GetProcAddress = { FA 8B 34 00 }
        $or60hAddShl1Hash32_LoadLibraryA = { 86 57 0D 00 }
        $addRor13Hash32_GetProcAddress = { 6F E0 53 E5 }
        $addRor13Hash32_LoadLibraryA = { 72 60 77 74 }
        $rol8Xor0xB0D4D06Hash32_GetProcAddress = { 43 50 0F 5F }
        $rol8Xor0xB0D4D06Hash32_LoadLibraryA = { 47 1A 57 5F }
        $ror13AddHash32DllSimple_GetProcAddress = { C1 C6 39 EA }
        $ror13AddHash32DllSimple_LoadLibraryA = { A5 18 3A 5A }
        $shr2Shl5XorHash32_GetProcAddress = { AF 34 50 93 }
        $shr2Shl5XorHash32_LoadLibraryA = { 5B 75 8A F0 }
        $rol5XorHash32_GetProcAddress = { DB B6 B6 E5 }
        $rol5XorHash32_LoadLibraryA = { 3B 00 A1 B4 }

    condition:
        all of ($addRol5HashOncemore32*) or
        all of ($imul21hAddHash32*) or
        all of ($ror7AddHash32*) or
        all of ($shl7SubHash32DoublePulser*) or
        all of ($imul83hAdd*) or
        all of ($xorShr8Hash32*) or
        all of ($or23hXorRor17Hash32*) or
        all of ($shl7Shr19XorHash32*) or
        all of ($rol3XorHash32*) or
        all of ($ror13AddHash32Sub20h*) or
        all of ($crc32*) or
        all of ($chAddRol8Hash32*) or
        all of ($ror13AddHash32Dll*) or
        all of ($playWith0xedb88320Hash*) or
        all of ($rol9AddHash32*) or
        all of ($crc32_bzip2*) or
        all of ($ror9AddHash32*) or
        all of ($ror11AddHash32*) or
        all of ($rol7AddHash32*) or
        all of ($ror13AddHash32*) or
        all of ($ror13AddHash32Sub1*) or
        all of ($rol3XorEax*) or
        all of ($xorRol9Hash32*) or
        all of ($rol9XorHash32*) or
        all of ($rol5AddHash32*) or
        all of ($poisonIvyHash*) or
        all of ($rol7XorHash32*) or
        all of ($crc32Xor0xca9d4d4e*) or
        all of ($playWith0xe8677835Hash*) or
        all of ($addRor13HashOncemore32*) or
        all of ($shl7Shr19AddHash32*) or
        all of ($or21hXorRor11Hash32*) or
        all of ($or60hAddShl1Hash32*) or
        all of ($addRor13Hash32*) or
        all of ($rol8Xor0xB0D4D06Hash32*) or
        all of ($ror13AddHash32DllSimple*) or
        all of ($shr2Shl5XorHash32*) or
        all of ($rol5XorHash32*)
}
