rule dotstatsuite_data_explorer_tests: override {
  meta:
    description             = "dotstatsuite-data-explorer Playwright e2e test files"
    js_eval_fx_str_multiple = "low"
    js_eval_fx_str          = "low"
    js_eval                 = "low"

  strings:
    $testid_selector = "testidSelector"
    $change_vibe     = "changeVibe"

  condition:
    filesize < 16KB and all of them
}
