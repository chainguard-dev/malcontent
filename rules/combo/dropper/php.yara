
rule php_copy_url {
  meta:
    ref = "kinsing"
  strings:
    $php = "<?php"
    $copy = /copy\([\'\"]http/
  condition:
    all of them
}
