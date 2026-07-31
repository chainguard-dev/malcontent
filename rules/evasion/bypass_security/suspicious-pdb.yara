rule high_pdb: high windows {
  meta:
    description = "high PDB (Windows Program Database) reference"

  strings:
    // extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
    $ref = /[a-zA-Z]{0,16}(Dropper|Bypass|Injection|Potato)\.pdb/ nocase

    // same token without the leading context class, used only for counting: the
    // [a-zA-Z]{0,16} prefix makes $ref report one match per start offset (17 for
    // a single "DependencyInjection.pdb"), so #ref is not an occurrence count
    $c_pdb = /(Dropper|Bypass|Injection|Potato)\.pdb/ nocase

    $not_dep  = "DepInjection.pdb"
    $not_dep2 = "DependencyInjection.pdb"

  condition:
    // both accepted names hold exactly one "Injection.pdb", so a count above their
    // combined tally means the file carries a .pdb name neither accounts for; one
    // dependency-injection symbol no longer excuses a real dropper name alongside it
    $ref and #c_pdb > #not_dep + #not_dep2
}
