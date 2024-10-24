rule bash_js : override {
  meta:
    description = "bash.js; prism_bash.js"
    infection_killer = "medium"
  strings:
    $bash = "BASH"
    $prism = "(Prism)"
    $js1 = "function"
    $js2 = "var"
  condition:
    filesize < 32KB and $bash and $prism and all of ($js*)
}
