rule malware_lvscam_phpwebshell {
    meta:
        description = "PHP malware used in lucky visitor scam"
        author = "JPCERT/CC Incident Response Group"
        hash = "1c7fe8ee16da73a337c1502b1fe600462ce4b9a3220f923d02f900ea61c63020"
        hash = "aebeadc7a6c5b76d842c7852705152930c636866c7e6e5a9fa3be1c15433446c"

    strings:
        $s1 = "http://136.12.78.46/app/assets/api"
        $s2 = "['a'] == 'doorway2')"
        $s3 = "['sa'] == 'eval')"

    condition:
        2 of them
}

rule malware_seospam_php {
     meta:
        description = "PHP using Japanese SEO Spam"
        author = "JPCERT/CC Incident Response Group"
        hash = "619cf6a757a1967382287c30d95b55bed3750e029a7040878d2f23efda29f8f0"

     strings:
        $func1 = "function dageget($" ascii
        $func2 = "function sbot()" ascii
        $func3 = "function st_uri()" ascii
        $func4 = "function is_htps()" ascii
        $query1 = /sha1\(sha1\(@\$_GET\[\"(a|\\x61|\\141)"\]\)\);/ ascii
        $query2 = /sha1\(sha1\(@\$_GET\[\"(b|\\x62|\\142)"\]\)\);/ ascii
        $query3 = /@\$_GET\[\"(p|\\x70|\\160)(d|\\x64|\\144)\"\]/ ascii
        $content1 = "nobotuseragent" ascii
        $content2 = "okhtmlgetcontent" ascii
        $content3 = "okxmlgetcontent" ascii
        $content4 = "pingxmlgetcontent" ascii

     condition:
       7 of them
}

rule malware_ruoji_phpwebshell {
     meta:
        description = "ruoji webshell"
        author = "JPCERT/CC Incident Response Group"
        hash = "8a389390a9ce4aba962e752218c5e9ab879b58280049a5e02b9143e750265064"

     strings:
        $s1 = "zxcszxctzxcrzxc_zxcrzxcezxc" ascii
        $s2 = "<?php if ($_COOKIE[" ascii
        $s3 = "'] !== $_GET['" ascii
        $s4 = "'] && @md5($_GET['" ascii
        $s5 = "']) === @md5($_GET['" ascii

     condition:
       4 of them
}

rule malware_spider_phpwebshell {
     meta:
        description = "Spider PHP Shell"
        author = "JPCERT/CC Incident Response Group"
        hash = "ae17d97d8f7fd5216776e2ec457a2d60567bc6cc175206d0641861f71a7e7614"

     strings:
        $s1 = "<title> Spider PHP Shell" ascii
        $s2 = "<li><a href=\"?s=k\" id=\"t_10\" onclick=\"switchTab('t_10')\" target=\"main\"> Linux" ascii
        $s3 = "if($_COOKIE['admin_spiderpass'] != md5($password))" ascii
        $s4 = "case \"b\" : Guama_b(); break;" ascii

     condition:
       2 of them
}
