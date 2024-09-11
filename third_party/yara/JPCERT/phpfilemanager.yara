rule webshell_phpfilemanager_str {
     meta:
        description = "Webshell PHP File Manager (2017-08-07)"
        author = "JPCERT/CC Incident Response Group"
        hash = "a8bd19d39700bce00fe7a525c551b04e36352d847e73c9741bb2816a3ea018df"

     strings:
        $str1 = "https://github.com/alexantr/filemanager"
        $str2 = "kbuvNx+mOcbN9taGBlpLAWf9nX8EGADoCfqkKWV/cgAAAABJRU5ErkJggg=="
        $str3 = "9oeiCT9Fr1cL/gmp125aUc4P+B85iX+qJ/la0k/Ze0D0T0j93jXTpv0BYUGhQhdSooYAAAAASUVO"
        $str4 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAEElEQVR42mL4//8/A0CAAQAI/AL+26JNFgAAAABJRU5ErkJggg=="
        $str5 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAKklEQVR42mL5//8/Azbw+PFjrOJMDCSCUQ3EABZc4S0rKzsaSvTTABBgAMyfCMsY4B9iAAAAAElFTkSuQmCC"

     condition:
       uint32(0) == 0x68703F3C and 3 of ($str*)
}
