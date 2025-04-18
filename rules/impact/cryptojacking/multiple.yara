rule multiple_pools: critical {
  meta:
    description = "References multiple types of mining pools"

  strings:
    $ = "2miners" fullword
    $ = "acc-pool" fullword
    $ = "cruxpool" fullword
    $ = "ethermine" fullword
    $ = "ezil" fullword
    $ = "f2pool" fullword
    $ = "flexpool" fullword
    $ = "flypool" fullword
    $ = "hashrate" fullword
    $ = "herominers" fullword
    $ = "k1pool" fullword
    $ = "minerpool" fullword
    $ = "nanopool" fullword
    $ = "rplant" fullword
    $ = "vipor" fullword
    $ = "whales" fullword
    $ = "woolypooly" fullword

    $not_pypi_index = "testpack-id-lb001"

  condition:
    filesize < 100MB and 4 of them and none of ($not*)
}
