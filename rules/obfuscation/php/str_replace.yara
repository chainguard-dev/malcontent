

rule php_str_replace_obfuscation : high {
  meta:
    description = "calls str_replace and uses obfuscated functions"
    hash_2024_2024_Inull_Studio_err = "5dbab6891fefb2ba4e3983ddb0d95989cf5611ab85ae643afbcc5ca47c304a4a"
    hash_2024_2024_Inull_Studio_err = "5dbab6891fefb2ba4e3983ddb0d95989cf5611ab85ae643afbcc5ca47c304a4a"
  strings:
    $str_replace = "str_replace"
    $o_dynamic_single = /\$\w {0,2}= \$\w\(/
    $o_single_concat = /\$\w . \$\w . \$\w ./
    $o_single_set = /\$\w = \w\(\)\;/
    $o_recursive_single = /\$\w\( {0,2}\$\w\(/
  condition:
    filesize < 65535 and $str_replace and 2 of ($o*)
}
