import unittest
from pathlib import Path

from build_scripts.mask_awk_for_shell_scan import (
    mask_single_quoted_awk_programs,
)


class MaskAwkForShellScanTests(unittest.TestCase):
    def test_masks_multiline_awk_functions_but_preserves_line_shape(self):
        source = """value=$(printf '%s\\n' "$data" | awk \\
  -v wanted="$wanted" '\n+  function helper(value) { return value }\n+  BEGIN { print helper(wanted) }\n+')\n+"""
        masked = mask_single_quoted_awk_programs(source)
        self.assertEqual(masked.count("\n"), source.count("\n"))
        self.assertNotIn("function helper", masked)
        self.assertIn('value=$(printf', masked)
        self.assertIn("')", masked)

    def test_does_not_hide_real_shell_function_bashism(self):
        source = "function broken { echo no; }\n"
        self.assertEqual(mask_single_quoted_awk_programs(source), source)

    def test_preserves_shell_code_after_inline_awk_program(self):
        source = "awk 'function ok() { return 1 }' input; function bad { :; }\n"
        masked = mask_single_quoted_awk_programs(source)
        self.assertNotIn("function ok", masked)
        self.assertIn("function bad", masked)

    def test_does_not_mask_an_awk_word_inside_an_echo(self):
        source = "echo \"awk 'function still_visible() {}'\"\n"
        self.assertEqual(mask_single_quoted_awk_programs(source), source)

    def test_skips_quoted_field_separator_before_multiline_program(self):
        source = (
            "value=$(awk -F '\\t' \\\n"
            "  -v wanted=\"$wanted\" '\n"
            "function helper(value) { return value }\n"
            "BEGIN { print helper(wanted) }\n"
            "' input); function broken { :; }\n"
        )
        masked = mask_single_quoted_awk_programs(source)
        self.assertEqual(masked.count("\n"), source.count("\n"))
        self.assertIn("-F '\\t'", masked)
        self.assertNotIn("function helper", masked)
        self.assertIn("function broken", masked)

    def test_skips_quoted_option_values_in_attached_and_separate_forms(self):
        for options in ("-F'|'", "-v 'wanted=value'", "-v wanted='value'",
                        "-vwanted='value'", "-F '|' -v wanted='value'"):
            with self.subTest(options=options):
                source = f"awk {options} 'function helper() {{ return 1 }}' input\n"
                masked = mask_single_quoted_awk_programs(source)
                self.assertIn(options, masked)
                self.assertNotIn("function helper", masked)

    def test_release_verifiers_keep_shell_and_hide_awk_functions(self):
        root = Path(__file__).resolve().parents[2]
        for relative in ("install.sh", "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/release-verify.sh"):
            with self.subTest(path=relative):
                source = (root / relative).read_text(encoding="utf-8")
                masked = mask_single_quoted_awk_programs(source)
                self.assertEqual(masked.count("\n"), source.count("\n"))
                self.assertNotIn("function fail()", masked)
                self.assertNotIn("function token(value)", masked)
                self.assertNotIn("function hex(value, size)", masked)
                self.assertIn("release_verify_fail()", masked)

    def test_does_not_use_comment_quote_after_dynamic_awk_program(self):
        source = "awk -F '\\t' \"$program\" # it's a comment\nfunction broken { :; }\n# '\n"
        self.assertEqual(mask_single_quoted_awk_programs(source), source)

    def test_does_not_mask_shell_after_awk_option_command_boundary(self):
        for boundary in ("; echo", "| echo", "#", "# comment"):
            with self.subTest(boundary=boundary):
                source = f"awk -F '\\t' {boundary} 'ignored\nfunction broken {{ :; }}\n'\n"
                self.assertEqual(mask_single_quoted_awk_programs(source), source)

    def test_quoted_comment_marker_inside_option_does_not_end_awk_command(self):
        source = "awk -F '\\t' -v wanted=\"#not a comment\" 'function helper() { return 1 }' input\n"
        self.assertNotIn("function helper", mask_single_quoted_awk_programs(source))


if __name__ == "__main__":
    unittest.main()
