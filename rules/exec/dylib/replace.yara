rule java_replacement_class: medium java {
  meta:
    description = "runtime override of a class"
    filetypes   = "class,java"

  strings:
    $replace = "loadReplacementClass"

  condition:
    any of them
}
