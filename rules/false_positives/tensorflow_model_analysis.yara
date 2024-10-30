rule tfjs_predict_extractor_util: override {
  meta:
    description      = "tfjs_predict_extractor_util.py"
    py_dropper_chmod = "medium"

  strings:
    $copyright_google       = "# Copyright 2019 Google LLC"
    $subprocess_chmod       = "subprocess.check_call(['chmod', '+x', path])"
    $tfjs_predict_extractor = "Utilities for tfjs_predict_extractor."
    $tfjs_url_linux         = "http://storage.googleapis.com/tfjs-inference/tfjs-inference-linux"
    $tfjs_url_macos         = "http://storage.googleapis.com/tfjs-inference/tfjs-inference-macos"

  condition:
    all of them
}
