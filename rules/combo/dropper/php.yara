rule php_copy_url: high {
  meta:
    ref = "kinsing"

  strings:
    $php  = "<?php"
    $copy = /copy\([\'\"]http/

  condition:
    all of them
}
