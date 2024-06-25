
rule grayware_sites : high {
  meta:
    description = "References websites that host code that can be used maliciously"
    credit = "Initially ported from https://github.com/jvoisin/php-malware-finder"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2015_Resources_shell = "f257f2f97bf5cf9d7a0021046bb3d2a0b7cd16e38b152f6247c6e1f142864e52"
  strings:
    $ = "1337day.com"
    $ = "antichat.ru"
    $ = "b374k"
    $ = "ccteam.ru"
    $ = "crackfor"
    $ = "darkc0de"
    $ = "egyspider.eu"
    $ = "exploit-db.com"
    $ = "fopo.com.ar"
    $ = "hashchecker.com"
    $ = "hashkiller.com"
    $ = "md5crack.com"
    $ = "md5decrypter.com"
    $ = "milw0rm.com"
    $ = "milw00rm.com"
    $ = "packetstormsecurity"
    $ = "pentestmonkey.net"
    $ = "phpjiami.com"
    $ = "shodan.io"
    $ = "github.com/b374k/b374k"
    $ = "mumaasp.com"
  condition:
    any of them
}
