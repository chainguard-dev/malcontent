rule xor_terms: high {
  meta:
    description = "terms obfuscated using xor"

  strings:
    $LIBRARY  = "LIBRARY" xor(1-31)
    $LIBRARY2 = "LIBRARY" xor(33-255)
    $INFECT   = "INFECT" xor(1-31)
    $INFECT2  = "INFECT" xor(33-255)
    $MAGIC    = "MAGIC" xor(1-31)
    $MAGIC2   = "MAGIC" xor(33-255)
    $plugin   = "plugin" xor(1-31)
    $plugin2  = "plugin2" xor(33-255)
    $debug    = "debug" xor(1-31)
    $debug2   = "debug2" xor(33-255)
    $evil     = " evil " xor(1-31)
    $evil2    = " evil " xor(33-255)
    $environ  = "environ" xor(1-31)
    $environ2 = "environ" xor(33-255)

    $xterm  = "xterm" xor(1-31)
    $xterm2 = "xterm" xor(33-255)

  condition:
    filesize < 5MB and any of them
}
