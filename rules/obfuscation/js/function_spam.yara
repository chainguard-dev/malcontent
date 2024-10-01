rule js_const_func_obfuscation : critical {
	meta:
		description = "javascript obfuscation (excessive const functions)"
	strings:
		$const = "const "
		$function = "function("
		$return = "{return"

    $not_bootstrap = "* Copyright 2011-2024 The Bootstrap Authors (https://github.com/twbs/bootstrap/graphs/contributors)"
		$not_bindonce1 = "* Bindonce - Zero watches binding for AngularJs"
		$not_bindonce2 = "@link https://github.com/Pasvaz/bindonce"
		$not_bindonce3 = "@author Pasquale Vazzana <pasqualevazzana@gmail.com>"
		$not_fb = "Copyright (c) Facebook, Inc. and its affiliates."
		$not_floating_ui_react_dom = "@floating-ui/react-dom"
		$not_grafana1 = "/*! For license information please see module.js.LICENSE.txt */"
		$not_grafana2 = "@grafana/data"
		$not_grafana3 = "@grafana/runtime"
		$not_grafana4 = "@grafana/ui"
		$not_lodash = "Released under MIT license <https://lodash.com/license>"
		$not_lodash2 = {4C 6F 64 61 73 68 20 3C 68 74 74 70 73 3A 2F 2F 6C 6F 64 61 73 68 2E 63 6F 6D 2F 3E}
		$not_mit = "This source code is licensed under the MIT license found in the * LICENSE file in the root directory of this source tree."
		$not_openjs = "Copyright OpenJS Foundation and other contributors <https://openjsf.org/>"
	condition:
		filesize < 256KB and #const > 32 and #function > 48 and #return > 64 and none of ($not_*)
}
