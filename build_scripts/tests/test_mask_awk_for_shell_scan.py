import unittest

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


if __name__ == "__main__":
    unittest.main()
