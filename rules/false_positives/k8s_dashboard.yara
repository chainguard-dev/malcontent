rule mode_php_js: override {
  meta:
    description  = "mode-php.js, mode-php_laravel_blade.js"
    php_executor = "high"

  strings:
    $ace_define             = "ace.define"
    $ace_lib                = "ace/lib"
    $ace_mode               = "ace/mode"
    $ace_require            = "ace.require"
    $mode_php_laravel_blade = "ace/mode/php_laravel_blade"
    $php_worker             = "ace/mode/php_worker"
    $php_worker2            = "PhpWorker"

  condition:
    6 of them
}
