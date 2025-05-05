rule java_replacement_class: medium java {
  meta:
    description = "runtime override of a class"
    filetypes   = "application/java-vm,text/x-jav"

  strings:
    $replace = "loadReplacementClass"

  condition:
    any of them
}
