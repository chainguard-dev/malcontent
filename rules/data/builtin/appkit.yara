rule appkit: high {
  meta:
    description = "Includes AppKit, a web3 blockchain library"

  strings:
    $ref  = "Price impact reflects the change in market price due to your trade"
    $ref2 = "Select which chain to connect to your multi"

  condition:
    any of them
}
