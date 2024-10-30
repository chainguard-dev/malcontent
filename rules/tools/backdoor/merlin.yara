rule merlin_c2: high {
  meta:
    description = "XOR'ed shellcode from Brute Ratel"
    author      = "Florian Roth"

  strings:
    // extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
    $ref = "main.Merlin" ascii fullword

  condition:
    any of them
}
