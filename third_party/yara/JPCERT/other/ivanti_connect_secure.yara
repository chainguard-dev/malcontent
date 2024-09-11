rule webshell_DSLog_str {
    meta:
        description = "Ivanti Connect Secure infected DSLog.pm backdoor"
        author = "JPCERT/CC Incident Response Group"
        hash = "88071ac4500021da896d0a92c935dcb9ca5c2dfe02caa0ee1b924d8b72ae404e"

    strings:
        $str1 = "my $ua = $ENV{HTTP_USER_AGENT};" ascii
        $str2 = "my $req = $ENV{QUERY_STRING};" ascii
        $str3 = "my @param = split(/&/, $req);" ascii
        $str4 = "system(${res[1]});" ascii
        $str5 = "$res[1] =~ tr/!-~/P-~!-O/;" ascii

    condition:
    	all of them
}
