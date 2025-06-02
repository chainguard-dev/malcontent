rule vimeo_psalm_md_php_override: override {
  meta:
    description = "Psalm MD files with PHP code excerpts"
    SIGNATURE_BASE_WEBSHELL_PHP_Dynamic = "harmless"
  strings:
    $ = "Emitted when calling a function on a non-callable variable"
    $ = "Emitted when calling a function on a value whose type Psalm cannot infer."
    $ = "Emitted when trying to use `null` as a `callable`"
    $ = "Emitted when trying to call a function on a value that may not be callable"
    $ = "Emitted when trying to call a function on a value that may be null"
  condition:
    any of them
}
