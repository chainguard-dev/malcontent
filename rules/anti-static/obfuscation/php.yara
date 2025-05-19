rule php_obfuscation: high {
  meta:
    description = "obfuscated PHP code"
    credit      = "Ported from https://github.com/jvoisin/php-malware-finder"

    filetypes = "php"

  strings:
    $php                 = "<?php"
    $o_crit_func_comment = /(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\(/
    $o_b374k             = "'ev'.'al'"
    $o_align             = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/
    $o_weevely3          = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/
    $o_c99_launcher      = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/
    $o_ninja             = /base64_decode[^;]+getallheaders/
    $o_variable_variable = /\$\{\$[0-9a-zA-z]+\}/
    $o_too_many_chr      = /(chr\([\d]+\)\.){8}/
    $o_var_as_func       = /\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/

    $not_php_function         = "function(){"
    $not_php_string_prototype = "String.prototype" fullword

  condition:
    filesize < 5242880 and $php and any of ($o*) and none of ($not*)
}

rule php_hex_functions: high {
  meta:
    description = "contains function references encoded in hex"

    filetypes = "php"

  strings:
    $h_globals         = "\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53" nocase
    $h_eval            = "\\x65\\x76\\x61\\x6C\\x28" nocase
    $h_exec            = "\\x65\\x78\\x65\\x63" nocase
    $h_system          = "\\x73\\x79\\x73\\x74\\x65\\x6d" nocase
    $h_preg_replace    = "\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65" nocase
    $h_http_user_agent = "\\x48\\124\\x54\\120\\x5f\\125\\x53\\105\\x52\\137\\x41\\107\\x45\\116\\x54" nocase
    $h_base64_decode   = "\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\\x28\\x67\\x7a\\x69\\x6e\\x66\\x6c\\x61\\x74\\x65\\x28" nocase
    $not_auto          = "AUTOMATICALLY GENERATED"

  condition:
    any of ($h*) and none of ($not*)
}

rule php_non_printable: medium {
  meta:
    description = "non-printable values unexpectedly passed to a function"
    credit      = "Ported from https://github.com/jvoisin/php-malware-finder"

    filetypes = "php"

  strings:
    $ref = /(function|return|base64_decode).{,64}[^\x09-\x0d\x20-\x7E]{3}/
    $php = "<?php"

  condition:
    filesize < 5242880 and all of them
}

rule php_oneliner: medium {
  meta:
    description = "sets up PHP and jumps directly into risky function"
    credit      = "Ported from https://github.com/jvoisin/php-malware-finder"

    filetypes = "php"

  strings:
    $php        = "<?php"
    $o_oneliner = /(<\?php|[;{}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\s*\(/

  condition:
    filesize < 5242880 and $php and any of ($o*)
}

rule small_reversed_function_names: critical {
  meta:
    description = "Contains function names in reverse"
    credit      = "Initially ported from https://github.com/jvoisin/php-malware-finder"
    filetypes   = "php"

  strings:
    $php             = "<?php"
    $create_function = "create_function"
    $r_system        = "metsys"
    $r_passthru      = "urhtssap"
    $r_include       = "edulcni"
    $r_shell_execute = "etucexe_llehs"
    $r_base64_decode = "edoced_46esab"

  condition:
    filesize < 64KB and $php and $create_function and any of ($r*)
}

rule php_str_replace_obfuscation: high {
  meta:
    description = "calls str_replace and uses obfuscated functions"
    filetypes   = "php"

  strings:
    $str_replace        = "str_replace"
    $o_dynamic_single   = /\$\w {0,2}= \$\w\(/
    $o_single_concat    = /\$\w . \$\w . \$\w ./
    $o_single_set       = /\$\w = \w\(\)\;/
    $o_recursive_single = /\$[a-zA-Z_]\w*\(\$[a-zA-Z_]\w*\(/

  condition:
    filesize < 65535 and $str_replace and 2 of ($o*)
}

rule php_obfuscated_concat: medium {
  meta:
    description = "obfuscated PHP concatenation"
    credit      = "Ported from https://github.com/jvoisin/php-malware-finder"
    filetypes   = "php"

  strings:
    $php    = "<?php"
    $concat = /\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\./

  condition:
    filesize < 64KB and $php and $concat
}

rule php_obfuscated_concat_long: high {
  meta:
    description = "obfuscated PHP concatenation (long)"
    credit      = "Ported from https://github.com/jvoisin/php-malware-finder"
    filetypes   = "php"

  strings:
    $php    = "<?php"
    $concat = /\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\./

  condition:
    filesize < 64KB and $php and $concat
}

rule obfuscated_concat_multiple: critical {
  meta:
    description = "obfuscated string concatenation (multiple)"
    filetypes   = "php"

  strings:
    $php    = "<?php"
    $concat = /\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\./

  condition:
    filesize < 64KB and $php and #concat > 2
}

rule php_short_concat: medium {
  meta:
    description = "concatenates short strings"
    ref         = "https://blog.sucuri.net/2024/07/new-variation-of-wordfence-evasion-malware.html?ref=news.risky.biz"
    filetypes   = "php"

  strings:
    $concat = /["'][\.\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,4}["']/

  condition:
    filesize < 64KB and $concat
}

rule php_short_concat_multiple: high {
  meta:
    description = "concatenates short strings (multiple)"
    ref         = "https://blog.sucuri.net/2024/07/new-variation-of-wordfence-evasion-malware.html?ref=news.risky.biz"
    filetypes   = "php"

  strings:
    $concat = /["'][\.\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,4}["']/

  condition:
    filesize < 64KB and #concat > 2
}

rule strrev_multiple: medium {
  meta:
    description = "reverses strings an excessive number of times"
    filetypes   = "php"

  strings:
    $ref  = "strrev("
    $ref2 = /strrev\(['"].{0,256}['"]\)/

  condition:
    filesize < 64KB and (#ref > 5) or (#ref2 > 5)
}

rule strrev_short: medium {
  meta:
    description = "reverses a short string"
    filetypes   = "php"

  strings:
    $ref = /strrev\(['"][\w\=]{0,5}['"]\)/

  condition:
    filesize < 64KB and $ref
}

rule strrev_short_multiple: high {
  meta:
    description = "reverses multiple short strings"
    filetypes   = "php"

  strings:
    $ref = /strrev\(['"][\w\=]{0,5}['"]\)/

  condition:
    filesize < 64KB and #ref > 3
}
