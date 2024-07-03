
rule generic_obfuscated_perl : high {
  meta:
	description = "Obfuscated PERL code"
    hash_1980_FruitFly_A_205f = "205f5052dc900fc4010392a96574aed5638acf51b7ec792033998e4043efdf6c"
    hash_1980_FruitFly_A_9968 = "9968407d4851c2033090163ac1d5870965232bebcfe5f87274f1d6a509706a14"
    hash_1980_FruitFly_A_bbbf = "bbbf73741078d1e74ab7281189b13f13b50308cf03d3df34bc9f6a90065a4a55"
  strings:
    $unpack_nospace = "pack'" fullword
    $unpack = "pack '" fullword
    $unpack_paren = "pack(" fullword
    $reverse = "reverse "
    $sub = "sub "
    $eval = "eval{"
  condition:
    filesize < 20971520 and $eval and 3 of them
}

rule powershell_format : high {
  meta:
    description = "obfuscated Powershell format string"
    author = "Florian Roth"
  strings:
    $ref = "}{0}\"-f " ascii wide
  condition:
    filesize < 16777216 and any of them
}

rule powershell_compact : medium windows {
  meta:
    description = "unusually compact PowerShell representation"
    author = "Florian Roth"
  strings:
    $InokeExpression = ");iex" ascii wide nocase
  condition:
    filesize < 16777216 and any of them
}

rule casing_obfuscation : medium windows {
  meta:
    description = "unusual casing obfuscation"
    author = "Florian Roth"
  strings:
    $ref = /  (sEt|SEt|SeT|sET|seT)  / ascii wide
  condition:
    filesize < 16777216 and any of them
}

rule powershell_encoded : high windows {
  meta:
    description = "Encoded Powershell"
    author = "Florian Roth"
  strings:
    $ref = / -[eE][decoman]{0,41} ['"]?(JAB|SUVYI|aWV4I|SQBFAFgA|aQBlAHgA|cgBlAG)/ ascii wide
  condition:
    filesize < 16777216 and any of them
}

rule php_str_replace_obfuscation : high {
  meta:
    description = "calls str_replace and uses obfuscated functions"
  strings:
    $str_replace = "str_replace"
    $o_dynamic_single = /\$\w {0,2}= \$\w\(/
    $o_single_concat = /\$\w . \$\w . \$\w ./
    $o_single_set = /\$\w = \w\(\)\;/
    $o_recursive_single = /\$\w\( {0,2}\$\w\(/
  condition:
    filesize < 65535 and $str_replace and 2 of ($o*)
}

rule php_oneliner : medium {
  meta:
    description = "sets up PHP and jumps directly into risky function"
    credit = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2023_0xShell_0xObs = "6391e05c8afc30de1e7980dda872547620754ce55c36da15d4aefae2648a36e5"
    hash_2023_0xShell_0xShellObs = "64771788a20856c7b2a29067f41be9cb7138c11a2cf2a8d17ab4afe73516f1ed"
    hash_2023_0xShell_1337 = "657bd1f3e53993cb7d600bfcd1a616c12ed3e69fa71a451061b562e5b9316649"
  strings:
    $php = /<\?[^x]/
    $o_oneliner = /(<\?php|[;{}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\s*\(/
  condition:
    filesize < 5242880 and $php and any of ($o*)
}

rule php_obfuscation : high {
  meta:
    description = "obfuscated PHP code"
    credit = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2023_0xShell_1337 = "657bd1f3e53993cb7d600bfcd1a616c12ed3e69fa71a451061b562e5b9316649"
    hash_2023_0xShell_index = "f39b16ebb3809944722d4d7674dedf627210f1fa13ca0969337b1c0dcb388603"
    hash_2023_0xShell_crot = "900c0453212babd82baa5151bba3d8e6fa56694aff33053de8171a38ff1bef09"
  strings:
    $php = /<\?[^x]/
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

rule php_obfuscated_concat : high {
  meta:
    description = "obfuscated PHP concatenation"
    credit = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2024_systembc_password = "236cff4506f94c8c1059c8545631fa2dcd15b086c1ade4660b947b59bdf2afbd"
    hash_2024_PHP_dclzougj = "3eb6ea176cee1e92ab3c684d16a5f820131a518478016643b454a53eaf123e63"
    hash_2024_PHP_wlstncyj = "1a1c97594340ede77bc814670eaf35eaba861f1f9519038582416c704796da0a"
  strings:
    $php = /<\?[^x]/
    $concat = /\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\./
  condition:
    filesize < 5242880 and $php and $concat
}

rule php_obfuscated_concat_multiple : critical {
  meta:
    description = "obfuscated PHP concatenation (multiple)"
    hash_2024_systembc_password = "236cff4506f94c8c1059c8545631fa2dcd15b086c1ade4660b947b59bdf2afbd"
    hash_2024_PHP_dclzougj = "3eb6ea176cee1e92ab3c684d16a5f820131a518478016643b454a53eaf123e63"
    hash_2024_PHP_wlstncyj = "1a1c97594340ede77bc814670eaf35eaba861f1f9519038582416c704796da0a"
  strings:
    $php = /<\?[^x]/
    $concat = /\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\.\$[A-Za-z0-9]{0,4}\[[0-9]+\]\./
  condition:
    filesize < 5242880 and $php and #concat > 3
}

rule base64_str_replace : medium {
  meta:
    description = "creatively hidden forms of the term 'base64'"
  strings:
    $a = /ba.s.e64/
    $b = /b.a.s.6.4/
    $c = /b.a.se.6.4/
  condition:
    any of them
}

rule gzinflate_str_replace : critical {
  meta:
    description = "creatively hidden forms of the term 'gzinflate'"
  strings:
    $a = /g.z.inf.l.a/
    $b = /g.z.i.n.f.l/
    $c = /g.z.in.f.l/
  condition:
    any of them
}
