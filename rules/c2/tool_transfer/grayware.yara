rule grayware_sites: high {
  meta:
    description = "References websites that host code that can be used maliciously"
    credit      = "Initially ported from https://github.com/jvoisin/php-malware-finder"

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
    $ = "github.com/b374k/b374k"
    $ = "mumaasp.com"

  condition:
    any of them
}

rule shodan_io: medium {
  meta:
    description = "References shodan.io"

  strings:
    $ = "shodan.io"

  condition:
    any of them
}
