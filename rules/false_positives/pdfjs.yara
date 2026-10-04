// pdf.js vendors a Brotli decoder whose static dictionary is stored XOR 3
// encoded, so its plain words surface as xor_* matches
rule pdfjs_worker_min: override {
  meta:
    description = "minified or rebundled pdfjs-dist PDF.js worker"
    xor_certs   = "low"
    xor_terms   = "low"
    xor_url     = "low"

  strings:
    $editor  = /pdfjs_internal_editor_/
    $handler = /WorkerMessageHandler/

  condition:
    filesize < 3MB and all of them
}
