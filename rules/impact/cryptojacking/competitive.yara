rule killer_miner_panchansminingisland: critical {
  meta:
    description = "crypto miner virus"
    filetypes   = "elf"

  strings:
    $ = "killer" fullword
    $ = "miner" fullword
    $ = "p2p" fullword
    $ = "protector" fullword
    $ = "rootkit" fullword
    $ = "spreader" fullword
    $ = "updater" fullword

    $not_pypi_index = "testpack-id-lb001"
    $not_vale       = "github.com/errata-ai/vale"

  condition:
    filesize < 120MB and 6 of them and none of ($not*)
}
