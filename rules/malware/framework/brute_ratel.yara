rule brute_ratel_c4: high {
  meta:
    description = "XOR'ed shellcode from Brute Ratel"
    author      = "Florian Roth"

  strings:
    // extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
    $ref = "\x48\x83\xec\x50\x4d\x63\x68\x3c\x48\x89\x4d\x10" xor

  condition:
    any of them
}
