rule havoc_c2_xor: high {
  meta:
    description = "Havoc C2 implant"
    author      = "Florian Roth"

  strings:
    // extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
    $ref = "amsi.dllATVSH" ascii xor

  condition:
    any of them
}
