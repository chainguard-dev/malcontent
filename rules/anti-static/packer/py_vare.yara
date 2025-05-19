rule Vare_Obfuscator: critical {
  meta:
    description = "obfuscated with https://github.com/saintdaddy/Vare-Obfuscator"
    filetypes   = "py"

  strings:
    $var  = "__VareObfuscator__"
    $var2 = "Vare Obfuscator"

  condition:
    any of them
}
