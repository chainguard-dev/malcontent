rule malware_GETRdoor {
    meta:
        description = "ELF backdoor targeting FortiGate"
        author = "JPCERT/CC Incident Response Group"
        hash = "9da731d152c57e90cc95bc58aa55c0873005a747fda0d45529e964bdbc9dc18c"
        created_date = "2025-11-14"
        updated_date = "2025-11-20"

    strings:
        $s1 = "do_upload: file open failed" ascii
        $s2 = "/bin/snifferd" ascii
        $s3 = "tcp[(tcp[12]>>2):%d] = 0x%s" ascii
        $s4 = {00 34 37 34 35 35 34 35 32 00} // 47455452
        $s5 = "diagnose debug crashlog clear" ascii
        $s6 = {00 0A 30 78 30 30 30 30 00} // \n0x0000

    condition:
        uint32(0) == 0x464C457F and
        3 of them
}

rule malware_PELdoor {
    meta:
        description = "ELF backdoor"
        author = "JPCERT/CC Incident Response Group"
        hash = "7991d64a23a6630453b5a68d4082e713d501082535e53b7e84d98b8ec7eee7a9"
        created_date = "2025-11-20"
        updated_date = "2025-11-20"

    strings:
        $s1 = "sxcdewqaz!@#" ascii
        $s2 = ";7(Zu9YTsA7qQ#vw" ascii
        $s3 = "/var/run/miglogd000.pid" ascii
        $s4 = "/tmp/tmplog.tar" ascii
        $s5 = {66 3D FB 20 74 ?? 48 8B 45 ?? 0F B7 40 ?? 0F B7 C0 89 C7 E8 ?? ?? ?? ?? 66 3D 1D 02}

    condition:
        uint32(0) == 0x464C457F and
        3 of them
}

rule malware_SHADYMARY {
    meta:
        description = "SHADYMARY malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "1d347944b6cf8ecc54474149e9bcee0108919a293bed348a46228dca3d095618"
        created_date = "2025-11-20"
        updated_date = "2025-11-20"

    strings:
        $s1 = "/data2/libcrashpad.so" ascii
        $s2 = "/bin/smit" ascii
        $s3 = "injector return %d" ascii
        $s4 = "injector__call_syscall" ascii

    condition:
        uint32(0) == 0x464C457F and
        2 of them
}