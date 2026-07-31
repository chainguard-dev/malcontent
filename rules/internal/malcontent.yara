rule malcontent: harmless {
  meta:
    __malcontent__ = "true"
    description    = "match the malcontent binary (mal) and omit it unless --ignore-self=false"

  strings:
    $b_behavior   = "malcontent.Behavior"
    $f_action     = "malcontent/pkg/action"
    $f_malcontnet = "malcontent/pkg/malcontent"
    $f_compile    = "malcontent/pkg/compile"
    $f_profile    = "malcontent/pkg/profile"
    $f_render     = "malcontent/pkg/render"
    $f_report     = "malcontent/pkg/report"
    $f_version    = "malcontent/pkg/version"

    // malcontent was released as "bincapz" before the rename, and the sample
    // corpus still carries that build. Without these it is not recognised as
    // our own binary, so the ruleset it embeds as data gets scanned as content.
    $b_bz_behavior = "bincapz.Behavior"
    $f_bz_action   = "bincapz/pkg/action"
    $f_bz_report   = "bincapz/pkg/report"
    $f_bz_repo     = "chainguard-dev/bincapz"

  condition:
    3 of ($b_behavior, $f_action, $f_malcontnet, $f_compile, $f_profile, $f_render, $f_report, $f_version)
    or 3 of ($b_bz_behavior, $f_bz_action, $f_bz_report, $f_bz_repo)
}
