rule js_const_func_obfuscation : critical {
	meta:
		description = "javascript obfuscation (excessive const functions)"
	strings:
		$const = "const "
		$function = "function("
		$return = "{return"

        $not_bootstrap = "* Copyright 2011-2024 The Bootstrap Authors (https://github.com/twbs/bootstrap/graphs/contributors)"
		$not_fb = "Copyright (c) Facebook, Inc. and its affiliates."
		$not_mit = "This source code is licensed under the MIT license found in the * LICENSE file in the root directory of this source tree."
	condition:
		filesize < 256KB and #const > 32 and #function > 48 and #return > 64 and none of ($not_*)
}
