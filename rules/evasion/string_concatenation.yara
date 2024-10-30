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
