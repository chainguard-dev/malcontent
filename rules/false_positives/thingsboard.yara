rule thingsboard_scripts_js: override {
  meta:
    description      = "scripts.c88fecd373e21509.js"
    infection_killer = "medium"

  strings:
    $delimited1   = "|kill|killall|"
    $delimited2   = "|pkill|"
    $minified_js1 = "!function(A,N)"
    $minified_js2 = "throw new Error(\"Argument to polyad must be a positive number\");"
    $minified_js3 = "throw new Error(\"Selector \"+G+\" did not match a DOM element\");"

  condition:
    filesize < 256KB and all of them
}
