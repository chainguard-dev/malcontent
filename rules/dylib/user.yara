
rule dl_user : suspicious {
	meta:
		description = "dynamically executes code bundles"
		ref = "https://developer.apple.com/documentation/foundation/bundle"
	strings:
		$nsbundle = "NSBundle" fullword
		$close = "dlclose" fullword
		$error = "dlerror" fullword
		$open = "dlopen"  fullword
		$sym = "dlsym" fullword
	condition:
		all of them
}
