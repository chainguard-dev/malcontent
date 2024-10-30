rule common_hostname_blocklist: critical {
  meta:
    description = "avoids execution if host has a particular hostname"
    ref         = "https://www.zscaler.com/blogs/security-research/technical-analysis-bandit-stealer"

  strings:
    $ = "6C4E733F-C2D9-4" fullword
    $ = "AIDANPC" fullword
    $ = "ARCHIBALDPC" fullword
    $ = "B30F0242-1C6A-4" fullword
    $ = "BEE7370C-8C0C-4" fullword
    $ = "COMPNAME_4047" fullword
    $ = "DESKTOP-19OLLTD" fullword
    $ = "DESKTOP-1PYKP29" fullword
    $ = "DESKTOP-1Y2433R" fullword
    $ = "DESKTOP-5OV9S0O" fullword
    $ = "DESKTOP-7XC6GEZ" fullword
    $ = "DESKTOP-B0T93D6" fullword
    $ = "DESKTOP-BUGIO" fullword
    $ = "DESKTOP-CBGPFEE" fullword
    $ = "DESKTOP-D019GDM" fullword
    $ = "DESKTOP-DE369SE" fullword
    $ = "DESKTOP-KALVINO" fullword
    $ = "DESKTOP-NAKFFMT" fullword
    $ = "DESKTOP-VRSQLAG" fullword
    $ = "DESKTOP-WG3MYJS" fullword
    $ = "DESKTOP-WI8CLET" fullword
    $ = "EA8C2E2A-D017-4" fullword
    $ = "JOHN-PC" fullword
    $ = "JULIA-PC" fullword
    $ = "LISA-PC" fullword
    $ = "LUCAS-PC" fullword
    $ = "MARCI-PC" fullword
    $ = "NETTYPC" fullword
    $ = "ORELEEPC" fullword
    $ = "Q9IATRKPRH" fullword
    $ = "QarZhrdBpj" fullword
    $ = "RALPHS-PC" fullword
    $ = "SERVER-PC" fullword
    $ = "SERVER1" fullword
    $ = "TIQIYLA9TW5M" fullword
    $ = "WILEYPC" fullword
    $ = "WIN-5E07COS9ALR" fullword
    $ = "WORK" fullword
    $ = "XC64ZB" fullword
    $ = "d1bnJkfVlH" fullword

  condition:
    4 of them
}
