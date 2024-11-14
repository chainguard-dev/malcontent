rule malware_CobaltStrike_v3v4 {
          meta:
            description = "detect CobaltStrike Beacon in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html"
            hash1 = "154db8746a9d0244146648006cc94f120390587e02677b97f044c25870d512c3"
            hash2 = "f9b93c92ed50743cd004532ab379e3135197b6fb5341322975f4d7a98a0fcde7"

          strings:
            $v1 = { 73 70 72 6E 67 00 }
            $config3 = { 69 69 69 69 69 69 69 69 }
            $config4 = { 2E 2E 2E 2E 2E 2E 2E 2E }

          condition:
            $v1 and 1 of ($config*)
}

rule malware_CobaltStrike_beacon {
     meta:
        description = "CobaltStrike encoding code"
        author = "JPCERT/CC Incident Response Group"
        hash = "1957d8e71c1b14be9b9bde928b47629d8283b8165015647b429f83d11a0d6fb3"
        hash = "4b2b14c79d6476af373f319548ac9e98df3be14319850bec3856ced9a7804237"

     strings:
        $code1 = { 5? 8B ?? 83 C? 04 8B ?? 31 ?? 83 C? 04 5? 8B ?? 31 ?? 89 ?? 31 ?? 83 C? 04 83 E? 04 31 ?? 39 ?? 74 02 EB E? 5? FF E? E8 ?? FF FF FF }
        $code2 = { 5D 8B ?? 00 83 C? 04 8B ?? 00 31 ?? 83 C? 04 5? 8B ?? 00 31 ?? 89 ?? 00 31 ?? 83 C? 04 83 E? 04 31 ?? 39 ?? 74 02 EB E? 5? FF E? E8 ?? FF FF FF }

     condition:
        uint16(0) == 0xE8FC and
        $code1 in (6..200) or $code2 in (6..200)
}
