// Private rules for detecting install hooks
// These patterns are reused across capability and threat rules

private rule has_npm_hook
{
    strings:
        $npm_preinstall = /"preinstall"[\s]*:[\s]*"[^"]+/ nocase
        $npm_install = /"install"[\s]*:[\s]*"[^"]+/ nocase
        $npm_postinstall = /"postinstall"[\s]*:[\s]*"[^"]+/ nocase
        $npm_prepack = /"prepack"[\s]*:[\s]*"[^"]+/ nocase
        $npm_prepare = /"prepare"[\s]*:[\s]*"[^"]+/ nocase
    condition:
        any of them
}

private rule has_python_hook
{
    strings:
        $py_cmdclass_install = /cmdclass\s*=\s*\{[^}]*['"]install['"]\s*:/ nocase
        $py_cmdclass_develop = /cmdclass\s*=\s*\{[^}]*['"]develop['"]\s*:/ nocase
        $py_cmdclass_egg_info = /cmdclass\s*=\s*\{[^}]*['"]egg_info['"]\s*:/ nocase
    condition:
        any of them
}

private rule has_ruby_hook
{
    strings:
        // Gem install hooks
        $rb_gem_post_install = /\bGem\s*\.\s*post_install\b/ nocase
        $rb_gem_pre_install = /\bGem\s*\.\s*pre_install\b/ nocase
        $rb_gem_post_uninstall = /\bGem\s*\.\s*post_uninstall\b/ nocase
        $rb_gem_pre_uninstall = /\bGem\s*\.\s*pre_uninstall\b/ nocase

        // Gem::Installer hooks
        $rb_installer_post_install = /\bGem\s*::\s*Installer\s*\.\s*post_install\b/ nocase
        $rb_installer_pre_install = /\bGem\s*::\s*Installer\s*\.\s*pre_install\b/ nocase

        // Extension building (runs arbitrary code during install)
        $rb_extensions = /\bGem\s*::\s*Specification\s*\.\s*new\b.*\bextensions\s*=/ nocase
    condition:
        any of them
}

rule capability_process_hooks
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects install hooks that can execute code during package installation"
        identifies = "capability.process.hooks"
        severity = "low"
        specificity = "low"
        sophistication = "low"

        max_hits = 1
        path_include = "*/package.json,setup.py,*/setup.py,*.gemspec"

    condition:
        has_npm_hook or has_python_hook or has_ruby_hook
}
