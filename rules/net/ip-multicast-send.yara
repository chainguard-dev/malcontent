rule multicast {
  meta:
    description = "send data to multiple nodes simultaneously"
    ref         = "https://en.wikipedia.org/wiki/IP_multicast"

  strings:
    $multicast = "multicast" fullword

  condition:
    any of them
}
