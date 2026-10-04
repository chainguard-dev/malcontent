rule litellm_upload_security: override {
  meta:
    description                      = "litellm/proxy/rag_endpoints/upload_security.py"
    BINARYALERT_Eicar_Substring_Test = "harmless"

  strings:
    $docstring  = /Security controls for vector-store file uploads\./
    $scanner    = /class EicarTestMalwareScanner:/
    $scan_check = /if EICAR_TEST_SIGNATURE in content:/

  condition:
    filesize < 16KB and all of them
}
