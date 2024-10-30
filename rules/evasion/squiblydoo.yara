rule squiblydoo: high windows {
  meta:
    description = "uses regsrv32 to load a remote COM scriptlet"
    ref         = "https://socprime.com/blog/squiblydoo-attack-analysis-detection-and-mitigation/"
    author      = "Florian Roth"

  strings:
    // extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
    $class_id = "0000FEEDACDC}" ascii wide

  condition:
    any of them
}
