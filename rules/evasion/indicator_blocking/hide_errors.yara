rule php_suppressed_include: high {
  meta:
    description = "Includes a file, suppressing errors"
    credit      = "Inspired by DodgyPHP rule in php-malware-finder"

    hash_2024_Deobfuscated_r57Shell_0de93ccddbeddbea5954e4dacb37a6a9d343c1b3 = "aec20b9627d0cab7888d6bab79d56d849e9f06bc4045e2c13b629489630eac74"
    hash_2024_Deobfuscated_r57Shell_0fa5df7bbf035cb307867a5b5e783abfb0158976 = "f1e1d38c1f0461d2c1eea27eb1d6dcee966826bc1a2d3e34850cb0acc17e72ac"

  strings:
    $php           = "<?php"
    $include       = /@\s*include\s*/
    $not_snippet   = "snippet" fullword
    $not_copyright = "copyright" fullword

  condition:
    filesize < 5242880 and $php and $include and none of ($not*)
}
