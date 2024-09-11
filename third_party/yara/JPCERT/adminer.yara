rule webshell_adminer_4_7 {
     meta:
        description = "Webshell Adminer4.7"
        author = "JPCERT/CC Incident Response Group"
        hash = "7897ac51d8e50c550acae4204d0139cb2a5d0b6c11ca506978b237f8fe540fd1"

     strings:
        $str1 = "bruteForceKey()"
        $str2 = "https://www.adminer.org/"
        $str3 = "$_COOKIE[\"adminer_permanent\"]"
        $str4 = "process_list()"
        $str5 = "routine_languages()"
        $str6 = "$_COOKIE[\"adminer_key\"]"
        $str7 = "lzw_decompress($"
        $str8 = "preg_match('~^(database|table|columns|sql|indexes|"

     condition:
       uint32(0) == 0x68703F3C and 5 of ($str*)
}
