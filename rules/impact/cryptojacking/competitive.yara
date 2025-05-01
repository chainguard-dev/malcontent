rule killer_miner_panchansminingisland: critical {
  meta:
    description = "crypto miner virus"
    filetypes   = "application/x-elf"

  strings:
    $ = "killer"
    $ = "miner"
    $ = "p2p"
    $ = "protector"
    $ = "rootkit"
    $ = "spreader"
    $ = "updater"

    $not_pypi_index = "testpack-id-lb001"

  condition:
    filesize < 120MB and 6 of them and none of ($not*)
}
