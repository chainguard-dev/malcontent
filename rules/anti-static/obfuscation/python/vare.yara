rule Vare_Obfuscator: high {
  meta:
    description = "obfuscated with https://github.com/saintdaddy/Vare-Obfuscator"
    filetype    = "py"

  strings:
    $var  = "__VareObfuscator__"
    $var2 = "Vare Obfuscator"

  condition:
    any of them
}
