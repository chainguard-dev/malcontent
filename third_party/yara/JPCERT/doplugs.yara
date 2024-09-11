rule malware_DOPLUGS {
    meta:
        description = "DOPLUGS"
        author = "JPCERT/CC Incident Response Group"
        hash = "2a6015505c83113ff89d8a4be66301a3e6245a41"

    strings:
        $data1 = "CLSID" ascii wide
        /* Decode API Name
        8b 14 24:       MOV EDX,dword ptr [ESP]
        8a 5c 14 10:    MOV BL,byte ptr [ESP + EDX*0x1 + 0x10]
        8b 0c 24:       MOV ECX,dword ptr [ESP]
        88 df:          MOV BH,BL
        f6 d7:          NOT BH
        20 cf:          AND BH,CL
        f6 d1:          NOT CL
        20 d9:          AND CL,BL
        08 f9:          OR  CL,BH
        88 4c 14 10:    MOV byte ptr [ESP + EDX*0x1 + 0x10],CL
        */
        $enc1 = {8B 14 24 8A 5C 14 10 8B 0C 24 88 DF F6 D7 20 CF F6 D1 20 D9 08 F9 88 4C 14 10 8B 0C 24 41 EB}

        /* Decode API Name
        8b 14 24:       MOV EDX, dword ptr [ESP]
        89 d0:          MOV EAX, EDX
        80 e2 7c:       AND DL , ??
        f6 d0:          NOT AL
        24 83:          AND AL , ??
        08 c2:          OR  DL , ??
        */
        $enc2 = {8B 14 24 89 D0 80 E2 ?? F6 D0 24 ?? 08 ??}

    condition:
        uint16(0) == 0x5A4D and all of them
}

rule malware_DOPLUGSLoader {
    meta:
        description = "DOPLUGS Loader"
        author = "JPCERT/CC Incident Response Group"
        hash = "c7e9c45b18c8ab355f1c07879cce5a3e58620dd7"

    strings:
        $data1 = "NimMain" ascii wide
        /* RC4 Decrypt
        8b b4 b5 e8 fb ff ff:   MOV   ESI, dword ptr [EBP+ESI*0x4 + 0xfffffbe8]
        0f b6 44 3b 08:         MOVZX EAX, byte ptr[EBX + EDI*0x1 + 0x8]
        31 f0:                  XOR   EAX, ESI
        3d ff 00 00 00:         CMP   EAX, 0xff
        */
        $enc = {8b b4 b5 e8 fb ff ff 0f b6 44 3b 08 31 f0 3d ff 00 00 00}

    condition:
        uint16(0) == 0x5A4D and all of them
}