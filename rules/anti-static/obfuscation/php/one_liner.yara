rule php_oneliner: medium {
  meta:
    description                  = "sets up PHP and jumps directly into risky function"
    credit                       = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2023_0xShell_0xObs      = "6391e05c8afc30de1e7980dda872547620754ce55c36da15d4aefae2648a36e5"
    hash_2023_0xShell_0xShellObs = "64771788a20856c7b2a29067f41be9cb7138c11a2cf2a8d17ab4afe73516f1ed"
    hash_2023_0xShell_1337       = "657bd1f3e53993cb7d600bfcd1a616c12ed3e69fa71a451061b562e5b9316649"

  strings:
    $php        = "<?php"
    $o_oneliner = /(<\?php|[;{}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\s*\(/

  condition:
    filesize < 5242880 and $php and any of ($o*)
}
