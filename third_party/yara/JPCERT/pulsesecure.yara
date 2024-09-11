rule malware_pulsesecure_webshell {
     meta:
        description = "Webshell installed due to Pluse Connect Secure vulnerability(CVE-2021-22893)"
        author = "JPCERT/CC Incident Response Group"
        hash = "e3137135f4ad5ecdc7900a619d7f1b88ba252b963b38ae9a156299cc9bce92a1"
        hash = "0fe1758397e55084b05efcaeb056c10c7b991f6adbda10eee8c131b4b52f6534"
        hash = "1243b0bb3dc9ac428c76b57cf5f341923d49e35fcade0302c38d5d912d05fb7c"
        hash = "463023f0969b2b52bc491d8787de876e59f0d48446f908d16d1ce763bbe05ee9"

     strings:
        $webshellA1 = "Cache-Control: no-cache"
        $webshellA2 = "Content-type: text/html"
        $webshellA3 = "system("
        $webshellA4 = "if(CGI::param("
        $webshellA5 = "else{&main();}"
        $webshellB1 = "my $psalLaunch = CGI::param("
        $webshellB2 = "MIME::Base64::encode"
        $webshellB3 = "if ($psalLaunch ="
        $webshellB4 = "<button type=\"button\" onclick = \"submitData()\" >submit</botton>"
        $webshellB5 = "<input type=\"submit\" value=\"Run\">"
        $webshellB6 = "RC4($"
        $webshellB7 = "Could not execute command"
        $webshellC1 = "MIME::Base64::encode(RC4($"
        $webshellC2 = "Content-type:text/html"
        $webshellC3 = "HTTP_X_KEY"
        $webshellC4 = "HTTP_X_CMD"
        $webshellC5 = "HTTP_X_CNT"

     condition:
       all of ($webshellA*) or 4 of ($webshellB*) or all of ($webshellC*)
}
