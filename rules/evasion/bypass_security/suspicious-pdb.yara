rule high_pdb: high windows {
  meta:
    description = "high PDB (Windows Program Database) reference"

  strings:
    // extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
    $ref = /[a-zA-Z]{0,16}(Dropper|Bypass|Injection|Potato)\.pdb/ nocase

    $not_dep  = "DepInjection.pdb"
    $not_dep2 = "DependencyInjection.pdb"

  condition:
    $ref and none of ($not*)
}
