rule azure_kvkeys_index_js : override {
  meta:
    description = "index.js.map"
    lvt = "medium"
  strings:
    $azure = "Azure Key Vault"
    $license1 = "Copyright (c) Microsoft Corporation"
    $license2 = "Licensed under the MIT license"
  condition:
    filesize < 512KB and all of them
}
