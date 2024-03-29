rule base64_http_val : critical {
    meta:
        description = "contains base64 Python code"
    strings:
		$exec = "exec(" base64
		$eval = "eval(" base64
		$import = "__import__" base64
		$importlib = "importlib" base64
		$import_module = "import_module" base64
		$urllib = "urllib.request" base64
		$requests_get = "requests.get" base64
		$urlopen = "urlopen" base64
		$read = "read()" base64
		$decode = "decode()" base64
    condition:
        2 of them
}
