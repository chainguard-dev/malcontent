rule WaterPamola_eccube_injection {
     meta:
        description = "Water Pamola EC-CUBE injection script"
        author = "JPCERT/CC Incident Response Group"
        hash = "ab0b1dd012907aad8947dd89d66d5844db781955234bb0ba7ef9a4e0a6714b3a"

     strings:
        $code1 = "eval(function(p,a,c,k," ascii
        $code2 = "Bootstrap v3.3.4 (http://getbootstrap.com)" ascii
        $code3 = "https://gist.github.com/a36e28ee268bb8a3c6c2" ascii

     condition:
        all of them
}

rule WaterPamola_webshell_str {
     meta:
        description = "Chainese webshell using water pamola"
        author = "JPCERT/CC Incident Response Group"
        hash = "a619f1ff0c6a5c8fc26871b9c0492ca331a9f84c66fa7479d0069b7e3b22ba31"

     strings:
        $str1 = "$password"
        $str2 = "$register_key"
        $str3 = "$check_copyright"
        $str4 = "$global_version"
        $str5 = "Language and charset conversion settings"
        $str6 = "This is a necessary key"

     condition:
       uint32(0) == 0x68703F3C and all of them
}

rule WaterPamola_stealjs_str {
     meta:
        description = "Injection code from xss using water pamola"
        author = "JPCERT/CC Incident Response Group"
        hash = "af99c566c94366f0f172475feedeeaab87177e102c28e703c1f0eeb6f41a835e"

     strings:
        $str1 = "getSou("
        $str2 = "eval(function(p,a,c,k,"
        $str3 = "poRec"
        $str4 = "application/x-www-form-urlencoded"
        $str5 = "XMLHttpRequest"
        $str6 = "device_type_id"
        $str7 = "ownersstore"
        $str8 = "transactionid"
        $str9 = "admin_template"
        $str10 = "ec_ver"

     condition:
       6 of ($str*)
}

rule WaterPamola_webshell_eval {
     meta:
        description = "WaterPamola eval webshell"
        author = "JPCERT/CC Incident Response Group"
        hash = "9fc3b3e59fbded4329a9401855d2576a1f2d76c429a0b9c8ea7c9752cd7e8378"

     strings:
        $encode1 = "IEBldmF"
        $encode2 = "F6ciddKTs="
        $encode3 = "CRfUE9TVF"
        $str1 = "@package Page"
        $str2 = " str_replace"
        $str3 = "$vbl"

     condition:
        uint32(0) == 0x68703F3C and 4 of them
}

rule WaterPamola_cookieswebshell_php {
    meta:
        description = "Cookies_webshell in Water Pamola"
        author = "JPCERT/CC Incident Response Group"

    strings:
        $func1 = "@$_POST['cookie'];"
        $func2 = "explode(\"|\", $cookie);"
        $func3 = "openssl_pkey_get_public"
        $func4 = "openssl_public_decrypt"
        $func5 = "@create_function"
        $pubkey1 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPYZ72hGKjj5T+NBa7Y18yuRBC"

    condition:
        uint32(0) == 0x68703F3C and (4 of ($func*) or 1 of ($pubkey*))
}

rule WaterPamola_includewebshell_php {
    meta:
        description = "Include only_pcd webshell in Water Pamola"
        author = "JPCERT/CC Incident Response Group"

    strings:
        $func1 = "@INCLUDE_ONCE($_FILES['only_pcd']['tmp_name']);"

    condition:
        uint32(0) == 0x68703F3C and all of them
}

rule WaterPamola_javascriptstealer_encode {
     meta:
        description = "JavaScript stealer using water pamola"
        author = "JPCERT/CC Incident Response Group"

     strings:
        $func1 = ".split('|'),0,{}));"
        $func2 = "return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))"
        $func3 = "RegExp('\\b'+e(c)+'\\b','g'),k[c]);"
        $func4 = "while(c--)if(k[c])"

     condition:
       all of them
}

rule WaterPamola_phpstealer_encode {
     meta:
        description = "PHP stealer using water pamola"
        author = "JPCERT/CC Incident Response Group"

     strings:
        $func1 = "header(\"Access-Control-Allow-Origin: *\");"
        $func2 = "$ip=@$_SERVER['HTTP_CF_CONNECTING_IP'];"
        $func3 = "@$errlogs=fopen(pack('H*'"
        $func4 = "@$write=fwrite($errlogs,$mode);"

     condition:
       uint32(0) == 0x68703F3C and all of them
}
