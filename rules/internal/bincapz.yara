rule bincapz : harmless {
    meta:
		__bincapz__ = "true"
		description = "match the bincapz binary, to omit it unless --ignore-self=false"
    strings:
		$b_behavior = "bincapz.Behavior"
		$f_action = "bincapz/pkg/action"
		$f_bincapz = "bincapz/pkg/bincapz"
		$f_compile = "bincapz/pkg/compile"
		$f_profile = "bincapz/pkg/profile"
		$f_render = "bincapz/pkg/render"
        $f_report = "bincapz/pkg/report"
        $f_version = "bincapz/pkg/version"
    condition:
        $b_behavior and all of ($f_*)
}
