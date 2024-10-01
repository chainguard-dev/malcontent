rule js_const_func_obfuscation : critical {
	meta:
		description = "javascript obfuscation (integer parsing)"
		filetypes = "javascript"
	strings:
		$const = "const "
		$function = "function("
		$return = "{return"
		$parseInt = "parseInt"

		$not_grafana = "self.webpackChunkgrafana=self.webpackChunkgrafana"
	condition:
		filesize < 256KB and #const > 16 and #function > 32 and #parseInt > 8 and #return > 32 and none of ($not_*)
}
