import "pe"

rule malware_DtSftDriver {
    meta:
        description = "Hunt DtSftDriver"
        author = "JPCERT/CC Incident Response Group"
    strings:
        $func0 = {8B 57 10 8B 01 8B 00 57 52 53 FF D0}

    condition:
        (uint16(0) == 0x5A4D)
        and (pe.subsystem == pe.SUBSYSTEM_NATIVE)
        and pe.imports("FltCreateCommunicationPort","FLTMSR.SYS")
        and pe.imports("FltRegisterFilter","FLTMSR.SYS")
        and pe.imports("ZwQueryValueKey","ntoskrnl.exe")
        and (filesize > 20KB)
        and (filesize < 300KB)
        and ( all of ($func*) )
}

rule malware_DtSftDriverLoader {
    meta:
        description = "Hunt DtSftDriverLoader"
        author = "JPCERT/CC Incident Response Group"
    strings:
        /* Function Address: 0x0401330 :
        0F BE 1C 16                         movsx   ebx, byte ptr [esi+edx]
        33 D9                               xor     ebx, ecx
        81 E3 FF 00 00 00                   and     ebx, 0FFh
        C1 E9 08                            shr     ecx, 8
        33 0C 9D ?? ?? ?? ??                xor     ecx, KEY_GEN[ebx*4]
        42                                  inc     edx
        3B D0                               cmp     edx, eax             
        */
        $func0 = { 0F BE 1C 16 33 D9 81 E3 FF 00 00 00 C1 E9 08 33 0C 9D ?? ?? ?? ?? 42 3B D0 }

        /* Function Address: 0x0401910 :
        4A                                      dec     edx
        83 CA FC                                or      edx, 0FFFFFFFCh
        42                                      inc     edx
        8A 14 3A                                mov     dl, [edx+edi]
        30 14 08                                xor     [eax+ecx], dl
        40                                      inc     eax
        3B C6                                   cmp     eax, esi
        */
        $func1 = { 4A 83 CA FC 42 8A 14 3A 30 14 08 40 3B C6 }

    condition:
        (uint16(0) == 0x5A4D)
        and (filesize > 50KB)
        and (filesize < 600KB)
        and ( all of ($func*) )
}
