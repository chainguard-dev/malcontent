rule bincapz : harmless {
    meta:
		__bincapz__ = "true"
		description = "match the bincapz binary, to omit it unless --ignore-self=false"
    strings:
        $report = "bincapz/pkg/report"
		$behavior = "bincapz.Behavior"
		$render = "bincapz/pkg/render"
    condition:
        2 of them
}
