rule base64_str_replace: medium {
  meta:
    description                                     = "creatively hidden forms of the term 'base64'"
    hash_2024_2024_Inull_Studio_err                 = "5dbab6891fefb2ba4e3983ddb0d95989cf5611ab85ae643afbcc5ca47c304a4a"
    hash_2024_2024_Inull_Studio_err                 = "5dbab6891fefb2ba4e3983ddb0d95989cf5611ab85ae643afbcc5ca47c304a4a"
    hash_2024_2024_Inull_Studio_godzilla_xor_base64 = "699c7bbf08d2ee86594242f487860221def3f898d893071426eb05bec430968e"

  strings:
    $a = /ba.s.e64/
    $b = /b.a.s.6.4/
    $c = /b.a.se.6.4/

  condition:
    any of them
}

rule gzinflate_str_replace: critical {
  meta:
    description = "creatively hidden forms of the term 'gzinflate'"

  strings:
    $a = /g.z.inf.l.a/
    $b = /g.z.i.n.f.l/
    $c = /g.z.in.f.l/

  condition:
    any of them
}

rule funky_function: critical {
  meta:
    description = "creatively hidden forms of the term 'function'"
    filetypes   = "php"

  strings:
    $a = "'fu'.'nct'.'ion'"
    $b = "'f'.'unc'.'tion'"
    $c = "'fun'.'nc'.'tion'"
    $d = "'fun'.'ncti'.'on'"

  condition:
    any of them
}

rule php_obfuscation: high {
  meta:
    description             = "obfuscated PHP code"
    credit                  = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2023_0xShell_1337  = "657bd1f3e53993cb7d600bfcd1a616c12ed3e69fa71a451061b562e5b9316649"
    hash_2023_0xShell_index = "f39b16ebb3809944722d4d7674dedf627210f1fa13ca0969337b1c0dcb388603"
    hash_2023_0xShell_crot  = "900c0453212babd82baa5151bba3d8e6fa56694aff33053de8171a38ff1bef09"
    filetypes               = "php"

  strings:
    $php                 = "<?php"
    $o_crit_func_comment = /(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\(/
    $o_b374k             = "'ev'.'al'"
    $o_align             = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/
    $o_weevely3          = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/
    $o_c99_launcher      = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/
    $o_ninja             = /base64_decode[^;]+getallheaders/
    $o_variable_variable = /\${\$[0-9a-zA-z]+}/
    $o_too_many_chr      = /(chr\([\d]+\)\.){8}/
    $o_var_as_func       = /\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/

    $not_php_function         = "function(){"
    $not_php_string_prototype = "String.prototype" fullword

  condition:
    filesize < 5242880 and $php and any of ($o*) and none of ($not*)
}

rule php_hex_functions: high {
  meta:
    description              = "contains function references encoded in hex"
    hash_2023_0xShell_crot   = "900c0453212babd82baa5151bba3d8e6fa56694aff33053de8171a38ff1bef09"
    hash_2023_0xShell_login  = "7c8d783c489337251125204c4b7f9222d83058ed6872f55db1319a0be7337f05"
    hash_2023_0xShell_logout = "f8feafb93e55e75e9e52c5db3835e646e182b7910afa9152b112ff9d5a29a197"

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
    description                                                                               = "non-printable values unexpectedly passed to a function"
    credit                                                                                    = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2023_0xShell_adminer                                                                 = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2023_0xShell_wesoori                                                                 = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2024_UPX_0a07c056fec72668d3f05863f103987cc1aaec92e72148bf16db6cfd58308617_elf_x86_64 = "94f4de1bd8c85b8f820bab936ec16cdb7f7bc19fa60d46ea8106cada4acc79a2"

  strings:
    $ref = /(function|return|base64_decode).{,64}[^\x09-\x0d\x20-\x7E]{3}/
    $php = "<?php"

  condition:
    filesize < 5242880 and all of them
}

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
    description                     = "calls str_replace and uses obfuscated functions"
    hash_2024_2024_Inull_Studio_err = "5dbab6891fefb2ba4e3983ddb0d95989cf5611ab85ae643afbcc5ca47c304a4a"
    hash_2024_2024_Inull_Studio_err = "5dbab6891fefb2ba4e3983ddb0d95989cf5611ab85ae643afbcc5ca47c304a4a"

  strings:
    $str_replace        = "str_replace"
    $o_dynamic_single   = /\$\w {0,2}= \$\w\(/
    $o_single_concat    = /\$\w . \$\w . \$\w ./
    $o_single_set       = /\$\w = \w\(\)\;/
    $o_recursive_single = /\$\w\( {0,2}\$\w\(/

  condition:
    filesize < 65535 and $str_replace and 2 of ($o*)
}

rule php_obfuscated_concat: medium {
  meta:
    description                 = "obfuscated PHP concatenation"
    credit                      = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2024_systembc_password = "236cff4506f94c8c1059c8545631fa2dcd15b086c1ade4660b947b59bdf2afbd"
    hash_2024_PHP_dclzougj      = "3eb6ea176cee1e92ab3c684d16a5f820131a518478016643b454a53eaf123e63"
    hash_2024_PHP_wlstncyj      = "1a1c97594340ede77bc814670eaf35eaba861f1f9519038582416c704796da0a"

  strings:
    $php    = "<?php"
    $concat = /\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\./

  condition:
    filesize < 64KB and $php and $concat
}

rule php_obfuscated_concat_long: high {
  meta:
    description                 = "obfuscated PHP concatenation (long)"
    credit                      = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2024_systembc_password = "236cff4506f94c8c1059c8545631fa2dcd15b086c1ade4660b947b59bdf2afbd"
    hash_2024_PHP_dclzougj      = "3eb6ea176cee1e92ab3c684d16a5f820131a518478016643b454a53eaf123e63"
    hash_2024_PHP_wlstncyj      = "1a1c97594340ede77bc814670eaf35eaba861f1f9519038582416c704796da0a"

  strings:
    $php    = "<?php"
    $concat = /\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\./

  condition:
    filesize < 64KB and $php and $concat
}

rule obfuscated_concat_multiple: critical {
  meta:
    description                 = "obfuscated string concatenation (multiple)"
    hash_2024_systembc_password = "236cff4506f94c8c1059c8545631fa2dcd15b086c1ade4660b947b59bdf2afbd"
    hash_2024_PHP_dclzougj      = "3eb6ea176cee1e92ab3c684d16a5f820131a518478016643b454a53eaf123e63"
    hash_2024_PHP_wlstncyj      = "1a1c97594340ede77bc814670eaf35eaba861f1f9519038582416c704796da0a"

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

  strings:
    $concat = /["'][\.\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,4}["']/

  condition:
    filesize < 64KB and $concat
}

rule php_short_concat_multiple: high {
  meta:
    description = "concatenates short strings (multiple)"
    ref         = "https://blog.sucuri.net/2024/07/new-variation-of-wordfence-evasion-malware.html?ref=news.risky.biz"

  strings:
    $concat = /["'][\.\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,6}["'] {0,1}[\.\+] {0,1}["'][\w\=]{0,4}["']/

  condition:
    filesize < 64KB and #concat > 2
}

rule strrev_multiple: medium {
  meta:
    description = "reverses strings an excessive number of times"

  strings:
    $ref  = "strrev("
    $ref2 = /strrev\(['"].{0,256}['"]\)/

  condition:
    filesize < 64KB and (#ref > 5) or (#ref2 > 5)
}

rule strrev_short: medium {
  meta:
    description = "reverses a short string"

  strings:
    $ref = /strrev\(['"][\w\=]{0,5}['"]\)/

  condition:
    filesize < 64KB and $ref
}

rule strrev_short_multiple: high {
  meta:
    description = "reverses multiple short strings"

  strings:
    $ref = /strrev\(['"][\w\=]{0,5}['"]\)/

  condition:
    filesize < 64KB and #ref > 3
}
