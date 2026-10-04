rule nemo_skills_swebench: override {
  meta:
    description          = "nemo_skills/inference/eval/swebench.py"
    cd_root              = "medium"
    chmod_dangerous_exec = "medium"
    py_dropper_chmod     = "medium"

  strings:
    $generation_task = /class SweBenchGenerationTask\(GenerationTask\):/
    $generation_cfg  = /config_name="base_swebench_generation_config"/
    $nemo_import     = /from nemo_skills\.inference\.generate import GenerationTask/

  condition:
    filesize < 80KB and all of them
}
