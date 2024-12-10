rule malware_SysrvBot {
    meta:
        description = "detect SysrvBot"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "9df43de4920699bd51d4964b681bd2ce8315b189b812f92084f7c3e423610b2f"
        hash2 = "506d0ed05c5334cf4461380123eab85e46398220ed82386745f3d8ef3339adf9"

    strings:
        $a1 = "hello/controller/xmrig"
        $a2 = "hello/scan.(*Scanner)."
        $a3 = "hello/exp/exploit.go"

    condition:
        all of them
}

rule backdoor_SysrvBot_webshell {
    meta:
        description = "webshell used by SysrvBot"
        author = "JPCERT/CC Incident Response Group"
        hash = "e09206410a6a673eb1be11426c57277efd19c92f910df6f8f25a449333acb966"

    strings:
        $s1 = "bd82dad4c619d462" ascii
        $s2 = "$after[$i]^$key[$i+1&" ascii
        $s3 = "Decrypt(file_get_contents(\"php://input\"))" ascii
        $s4 = "@eval($" ascii

    condition:
        3 of them
}

rule backdoor_SysrvBot_tomcat {
    meta:
        description = "downloader used by SysrvBot"
        author = "JPCERT/CC Incident Response Group"
        hash = "1e2d12a65ea0f79ed8aaf5f14700ac1413375fcff7e600762f9ccdc268391f8b"

    strings:
        $s1 = "&echo ----file ROOT good----" ascii
        $s2 = "application.getRealPath(\"tomcat.jsp\").split(\"\\\\\\\\tomcat.jsp\");" ascii
        $s3 = "ldr.sh?tomcat)|bash" ascii

    condition:
        all of them
}

rule backdoor_SysrvBot_downloader {
    meta:
        description = "downloader used by SysrvBot"
        author = "JPCERT/CC Incident Response Group"
        hash = "a1fbaee0915edd8568fcea9868fd511adb43faf93bd0abd63788a61febcff13b"

    strings:
        $s1 = "echo \"Detected Zen4 CPU\"" ascii
        $s2 = "key $user@$host \"(curl $cc/" ascii
        $s3 = "$i/hugepages/hugepages-1048576kB/nr_hugepages" ascii

    condition:
        all of them
}