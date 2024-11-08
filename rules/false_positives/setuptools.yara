rule test_pyprojecttoml: override {
  meta:
    description     = "namespaces.py, test_pyprojecttoml.py"
    setuptools_eval = "low"

  strings:
    $example   = "EXAMPLE"
    $func1     = "def create_example("
    $func2     = "def verify_example("
    $func3     = "def test_read_configuration("
    $import    = "import setuptools"
    $kv        = "\"pyproject.toml\": EXAMPLE"
    $pyproject = "pyproject.toml"

  condition:
    filesize < 16KB and all of them
}

rule setuptools_namespaces: override {
  meta:
    description     = "namespaces.py"
    setuptools_eval = "low"

  strings:
    $func1     = "def iter_namespace_pkgs("
    $func2     = "def build_namespace_package("
    $func3     = "def build_pep420_namespace_package("
    $namespace = "namespace"
    $pyproject = "pyproject.toml"
    $tmpl1     = "tmpl = '__import__(\"pkg_resources\").declare_namespace(__name__)'"
    $tmpl2     = "tmpl = '__path__ = __import__(\"pkgutil\").extend_path(__path__, __name__)'"

  condition:
    filesize < 4KB and all of ($func*) and #namespace > 0 and $pyproject and all of ($tmpl*)
}

rule numba_support: override {
  meta:
    description     = "support.py"
    setuptools_eval = "low"

  strings:
    $comment    = "Assorted utilities for use in tests."
    $gh_issue   = "numba#"
    $import     = "from numba"
    $repository = "https://github.com/numba/numba"

  condition:
    filesize < 64KB and all of them
}
