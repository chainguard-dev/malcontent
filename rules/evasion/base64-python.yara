
rule base64_python_functions : critical {
  meta:
    description = "contains base64 Python code"
    hash_2023_0xShell_0xencbase = "50057362c139184abb74a6c4ec10700477dcefc8530cf356607737539845ca54"
    hash_2023_0xShell_wesobase = "17a1219bf38d953ed22bbddd5aaf1811b9380ad0535089e6721d755a00bddbd0"
    hash_2024_static_demonizedshell_static = "b4e65c01ab90442cb5deda26660a3f81bd400c205e12605536483f979023aa15"
  strings:
    $f_exec = "exec(" base64
    $f_eval = "eval(" base64
    $f_import_os = "import os" base64
    $f_import = "__import__" base64
    $f_importlib = "importlib" base64
    $f_import_module = "import_module" base64
    $f_urllib = "urllib.request" base64
    $f_requests_get = "requests.get" base64
    $f_urlopen = "urlopen" base64
    $f_read = "read()" base64
    $f_decode = "decode()" base64
    $f_b64decode = "base64.b64decode" base64
    $f_exc = "except Exception as" base64
    $f_os_system = "os.system" base64
    $f_os_popen = "os.popen" base64
      $f_thread = "threading.Thread" base64
    $f_os_environ = "os.environ" base64
    $f_with_open = "with open(" base64
    $not_js = " ?? " base64
    $not_js2 = " === " base64
    $not_js3 = "const" base64
    $not_js4 = "this." base64
    $not_js5 = "throw" base64
  condition:
    2 of ($f*) and none of ($not*)
}
