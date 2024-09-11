rule malware_SeaSpy_str {
     meta:
        description = "malware SeaSpy"
        author = "JPCERT/CC Incident Response Group"
        hash = "3f26a13f023ad0dcd7f2aa4e7771bba74910ee227b4b36ff72edc5f07336f115"
        hash = "5e3c128749f7ae4616a4620e0b53c0e5381724a790bba8314acb502ce7334df2" 

     strings:
        $msg1 = "<Network-Interface> <Listen-Port>" ascii fullword
        $msg2 = "<Network-Interface>. e.g." ascii fullword
        $msg3 = "Port value out of range." ascii fullword
        $msg4 = "enter open tty shell..." ascii fullword
        $msg5 = "NO port code" ascii fullword
        $msg6 = "pcap_lookupnet: %s" ascii fullword
        $msg7 = "pcap_compile" ascii fullword
        $msg8 = "pcap_setfilter" ascii fullword
        $msg9 = "Child process id:%d" ascii fullword
        $func1 = "open_tty_shell" ascii fullword
        $func2 = "start_pcap_listener" ascii fullword
        $func3 = "pcap_open_live" ascii fullword
        $func4 = "pcap_setfilter" ascii fullword
        $func5 = "reverse_shell" ascii fullword
        $key1 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuJDBIgz2Gb70ExKb7fww" ascii fullword

     condition:
       uint32(0) == 0x464C457F and
       (4 of ($msg*) or 4 of ($func*) or 1 of ($key*))
}