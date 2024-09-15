rule php_obfuscation : high {
  meta:
    description = "obfuscated PHP code"
    credit = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2023_0xShell_1337 = "657bd1f3e53993cb7d600bfcd1a616c12ed3e69fa71a451061b562e5b9316649"
    hash_2023_0xShell_index = "f39b16ebb3809944722d4d7674dedf627210f1fa13ca0969337b1c0dcb388603"
    hash_2023_0xShell_crot = "900c0453212babd82baa5151bba3d8e6fa56694aff33053de8171a38ff1bef09"
  strings:
    $php = "<?php"
    $o_crit_func_comment = /(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\(/
    $o_b374k = "'ev'.'al'"
    $o_align = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/
    $o_weevely3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/
    $o_c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/
    $o_ninja = /base64_decode[^;]+getallheaders/
    $o_variable_variable = /\${\$[0-9a-zA-z]+}/
    $o_too_many_chr = /(chr\([\d]+\)\.){8}/
    $o_var_as_func = /\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/
  condition:
    filesize < 5242880 and $php and any of ($o*)
}