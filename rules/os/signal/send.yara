rule kill: harmless {
  meta:
    syscall = "kill"
    pledge  = "proc"

  strings:
    $kill = "_kill" fullword
    $go   = "syscall.Kill" fullword
    $npm  = "process.kill" fullword

  condition:
    any of them
}

rule kill_unusual: high {
  meta:
    syscall     = "kill"
    pledge      = "proc"
    description = "sends unusual kill signal"

  strings:
    $kill = /kill -[245678]{1,3}/

  condition:
    any of them
}
