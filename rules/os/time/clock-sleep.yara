rule bsd_sleep: harmless {
  meta:
    description = "uses sleep to wait"

  strings:
    $_sleep = "_sleep" fullword
  // common in programs, doesn't seem important
  // $_usleep = "_usleep" fullword

  condition:
    any of them
}

rule setInterval: medium {
  meta:
    description = "uses setInterval to wait"

  strings:
    $setInterval = "setInterval("

  condition:
    filesize < 1MB and any of them
}

rule sleepRandom: medium {
  meta:
    description = "sleeps a random amount of time"

  strings:
    $sleep = /sleep rand\*\d{1,8}/

  condition:
    filesize < 1MB and any of them
}
