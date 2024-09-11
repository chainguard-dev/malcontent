rule tool_3proxy_strings {
    meta:
        description = "3Proxy tiny proxy server"
        author = "JPCERT/CC Incident Response Group"
        reference = "http://3proxy.ru/"
     strings:
        $str1 = "http://3proxy.ru/" ascii
        $str2 = "size of network buffer (default 4096 for TCP, 16384 for UDP)" ascii
        $str3 = "value to add to default client thread stack size" ascii
        $str4 = "Connect back not received, check connback client" ascii
        $str5 = "Failed to allocate connect back socket" ascii
        $str6 = "Warning: too many connected clients (%d/%d)" ascii
     condition:
        3 of ($str*)
}
