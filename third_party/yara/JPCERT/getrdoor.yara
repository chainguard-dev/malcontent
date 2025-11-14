rule malware_GETRdoor {
    meta:
        description = "ELF backdoor targeting FortiGate"
        author = "JPCERT/CC Incident Response Group"
        hash = "9da731d152c57e90cc95bc58aa55c0873005a747fda0d45529e964bdbc9dc18c"
        created_date = "2025-11-14"
        updated_date = "2025-11-14"

    strings:
        $s1 = "do_upload: file open failed" ascii
        $s2 = "/bin/snifferd" ascii
        $s3 = "tcp[(tcp[12]>>2):%d] = 0x%s" ascii
        $s4 = {00 34 37 34 35 35 34 35 32 00} // 47455452
        $s5 = "diagnose debug crashlog clear" ascii
        $s6 = {00 0A 30 78 30 30 30 30 00} // \n0x0000

    condition:
        3 of them
}