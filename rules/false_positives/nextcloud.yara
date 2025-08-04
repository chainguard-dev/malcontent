rule vimeo_psalm_md_php_override: override {
  meta:
    description                         = "Psalm MD files with PHP code excerpts"
    SIGNATURE_BASE_WEBSHELL_PHP_Dynamic = "harmless"
    SIGNATURE_BASE_WEBSHELL_PHP_Generic = "harmless"
    remote_eval_close                   = "harmless"

  strings:
    $ = "# Tainted Eval"
    $ = "Passing untrusted user input to `eval` calls is dangerous, as it allows arbitrary data to be executed on your server."
    $ = "Emitted when calling a function on a non-callable variable"
    $ = "Emitted when calling a function on a value whose type Psalm cannot infer."
    $ = "Emitted when trying to use `null` as a `callable`"
    $ = "Emitted when trying to call a function on a value that may not be callable"
    $ = "Emitted when trying to call a function on a value that may be null"

  condition:
    any of them
}
