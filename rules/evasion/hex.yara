rule node_hex_parse : high {
  meta:
    description = "converts hex data to ASCII"
    hash_2023_package_bgService = "36831e715a152658bab9efbd4c2c75be50ee501b3dffdb5798d846a2259154a2"
    hash_2023_getcookies_harness = "99b1563adea48f05ff6dfffa17f320f12f0d0026c6b94769537a1b0b1d286c13"
  strings:
    $ref = /Buffer\.from\(\w{0,16}, {0,2}'hex'\)/
  condition:
    $ref
}

rule php_hex_functons : high {
	meta:
		description = "contains function references encoded in hex"
    strings:
        $h_globals = "\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53" nocase
        $h_eval = "\\x65\\x76\\x61\\x6C\\x28" nocase
        $h_exec = "\\x65\\x78\\x65\\x63" nocase
        $h_system = "\\x73\\x79\\x73\\x74\\x65\\x6d" nocase
        $h_preg_replace = "\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65" nocase
        $h_http_user_agent = "\\x48\\124\\x54\\120\\x5f\\125\\x53\\105\\x52\\137\\x41\\107\\x45\\116\\x54" nocase
        $h_base64_decode = "\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\\x28\\x67\\x7a\\x69\\x6e\\x66\\x6c\\x61\\x74\\x65\\x28" nocase

		$not_auto = "AUTOMATICALLY GENERATED"
    condition:
        any of ($h*) and none of ($not*)
}
