
rule base64_http_val : critical {
  meta:
    description = "contains base64 Python code"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_pan_chan_6896 = "6896b02503c15ffa68e17404f1c97fd53ea7b53c336a7b8b34e7767f156a9cf2"
    hash_2023_pan_chan_73ed = "73ed0b692fda696efd5f8e33dc05210e54b17e4e4a39183c8462bcc5a3ba06cc"
  strings:
    $exec = "exec(" base64
    $eval = "eval(" base64
    $import_os = "import os" base64
    $import = "__import__" base64
    $importlib = "importlib" base64
    $import_module = "import_module" base64
    $urllib = "urllib.request" base64
    $requests_get = "requests.get" base64
    $urlopen = "urlopen" base64
    $read = "read()" base64
    $decode = "decode()" base64
    $b64decode = "base64.b64decode" base64
    $exc = "except Exception as" base64
    $thread = "threading.Thread" base64
  condition:
    2 of them
}
