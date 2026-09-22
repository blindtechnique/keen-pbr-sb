"""Pure checks for the lab's classifier shape; no network privileges needed."""

import unittest

from measure_list_set import classifier_lines


class ClassifierShapeTests(unittest.TestCase):
    def test_raw_is_mark_return_without_conntrack(self):
        _, lines = classifier_lines(["child_a", "child_b"], allow_conntrack=False)
        self.assertEqual(len(lines), 4)
        self.assertNotIn("CONNMARK", "\n".join(lines))
        self.assertTrue(lines[0].endswith("-j MARK --set-xmark 0x40000/0xffff0000"))
        self.assertTrue(lines[1].endswith("-j RETURN"))

    def test_mangle_keeps_save_between_mark_and_return(self):
        _, lines = classifier_lines(["child_a", "child_b"])
        self.assertEqual(len(lines), 6)
        self.assertIn("-j MARK", lines[0])
        self.assertIn("-j CONNMARK --save-mark --nfmask 0xffff0000 --ctmask 0xffff0000", lines[1])
        self.assertTrue(lines[2].endswith("-j RETURN"))
        self.assertTrue(all("child_a dst" in row for row in lines[:3]))
        self.assertTrue(all("child_b dst" in row for row in lines[3:]))

    def test_union_changes_only_set_reference_and_row_count(self):
        _, flat = classifier_lines(["child_a", "child_b"], allow_conntrack=False)
        _, union = classifier_lines(["parent"], allow_conntrack=False)
        self.assertEqual([row.replace("child_a", "parent") for row in flat[:2]], union)

    def test_common_selector_stays_on_every_physical_row(self):
        _, rows = classifier_lines(["a", "b"], selector="! -s 192.0.2.1")
        self.assertTrue(all("! -s 192.0.2.1" in row for row in rows))
        self.assertTrue(all("-p udp --dport 42042" in row for row in rows))

    def test_empty_list_never_becomes_a_match_all_rule(self):
        _, rows = classifier_lines([])
        self.assertEqual(rows, [])

    def test_sticky_path_returns_before_classifier(self):
        root, _ = classifier_lines(["a"], sticky=True)
        self.assertIn("--restore-mark", root[0])
        self.assertIn("-m mark ! --mark 0/0xffff0000 -j RETURN", root[1])
        self.assertEqual(root[2], "-A S01_ROOT -j S01_CLASS")

    def test_raw_never_claims_to_run_conntrack_save_restore(self):
        with self.assertRaises(ValueError):
            classifier_lines(["a"], sticky=True, allow_conntrack=False)


if __name__ == "__main__":
    unittest.main()
