rule malware_TokyoX_Loader {
    meta:
        description = "detect TokyoX Loader"
        author = "JPCERT/CC Incident Response Group"
        hash = "382b3d3bb1be4f14dbc1e82a34946a52795288867ed86c6c43e4f981729be4fc"

    strings:
        $str =  "NtAllocateVirtuaNtWriteVirtualMeNtCreateThreadEx"

    condition:
        (uint16(0) == 0x5A4D) and all of them
}

rule malware_TokyoX_RAT {
    meta:
        description = "detect TokyoX RAT"
        author = "JPCERT/CC Incident Response Group"
        hash = "46bf7ca79cd21289081e518a7b3bc310bbfafc558eb3356b987319fec4d15939"

    strings:
        $mz = { 74 6F 6B 79 6F 00 00 00 } // tokyo
        $format1 = "%08lX%04lX%04lX%02lx%02lx%02lx%02lx%02lx%02lx%02lx%02lx"
        $format2 = "%d-%d-%d %d:%d:%d" wide
        $uniq_path = "C:\\Windows\\SysteSOFTWARE\\Microsoft\\Windows NT\\Cu"

    condition:
        ($mz at 0 and all of ($format*)) or $uniq_path
}