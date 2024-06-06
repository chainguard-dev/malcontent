
rule generic_obfuscated_perl : high {
  meta:
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

rule php_obfuscation : high {
	meta:
		description = "obfuscation techniques seen in PHP malware"
		credit = "Ported from https://github.com/jvoisin/php-malware-finder"
    strings:
	    $php = /<\?[^x]/

        $o_eval = /(<\?php|[;{}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\s*\(/ nocase  // ;eval( <- this is dodgy
        $O_eval_comment = /(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\(/ nocase  // eval/*lol*/( <- this is dodgy
        $o_b374k = "'ev'.'al'"
        $o_align = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/  //b374k
        $o_weevely3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/  // weevely3 launcher
        $o_c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/  // http://bartblaze.blogspot.fr/2015/03/c99shell-not-dead.html
        $o_nano = /\$[a-z0-9-_]+\[[^]]+\]\(/ //https://github.com/UltimateHackers/nano
        $o_ninja = /base64_decode[^;]+getallheaders/ //https://github.com/UltimateHackers/nano
        $o_variable_variable = /\${\$[0-9a-zA-z]+}/
        $o_too_many_chr = /(chr\([\d]+\)\.){8}/  // concatenation of more than eight `chr()`
        $o_concat = /(\$[^\n\r]+\.){5}/  // concatenation of more than 5 words
        $o_concat_with_spaces = /(\$[^\n\r]+\. ){5}/  // concatenation of more than 5 words, with spaces
        $o_var_as_func = /\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/
        $o_comment = /\/\*([^*]|\*[^\/])*\*\/\s*\(/  // eval /* comment */ (php_code)
	condition:
		filesize < 5MB and $php and any of ($o*)
}
