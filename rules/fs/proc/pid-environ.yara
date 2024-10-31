
rule proc_environ : medium {
  meta:
    description = "accesses environment variables of other processes"
    hash_2024_enumeration_deepce = "76b0bcdf0ea0b62cee1c42537ff00d2100c54e40223bbcb8a4135a71582dfa5d"
  strings:
    $string = /\/proc\/[\*%{$][\w\}]{0,12}\/environ/
  condition:
    any of them
}
