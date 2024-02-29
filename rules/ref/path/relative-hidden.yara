
rule relative_hidden_launcher {
  meta:
    hash_2023_brawl_earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2023_Linux_Malware_Samples_05ca = "05ca0e0228930e9ec53fe0f0b796255f1e44ab409f91bc27d20d04ad34dcb69d"
    hash_2023_Linux_Malware_Samples_1ad6 = "1ad63158b9e0f214a111b4c815d08520c6282de5216e41f604612a12ce879efc"
    hash_2023_Linux_Malware_Samples_4c83 = "4c839f32e78fa11aa4ab961f045f7ca744c14d33d7a092dd9dfd1164cd7d4763"
    hash_2021_CoinMiner_Sysrv = "5f80945354ea8e28fa8191a37d37235ce5c5448bffb336e8db5b01719a69128f"
    hash_2021_Merlin_ispoh = "683e1eb35561da89db96c94f400daf41390bd350698c739c38024a1f621653b3"
    hash_2020_CoinMiner_nbtoz = "741af7d54a95dd3b4497c73001e7b2ba1f607d19d63068b611505f9ce14c7776"
    hash_2023_Linux_Malware_Samples_7955 = "7955542df199c6ce4ca0bb3966dcf9cc71199c592fec38508dad58301a3298d0"
  strings:
    $relative_hidden = /\.\/\.[\w][\w\/\.\_\-]{3,16}/ fullword

	$x_exec = "exec"
	$x_bash = "bash"
	$x_system = "system"
	$x_popen = "popen"

	$not_vscode = "vscode"
	$not_test = "./.test"
	$not_prove = ".proverc"
	$not_private = "/System/Library/PrivateFrameworks"
  condition:
	$relative_hidden and any of ($x*) and none of ($not*)
}
