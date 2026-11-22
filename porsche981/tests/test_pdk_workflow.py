import unittest

from simulate_pdk_workflow import model_cases


class PdkWorkflowSimulation(unittest.TestCase):
    def test_reference_model_cases_are_explicitly_separate_from_real_capabilities(self):
        rows = model_cases()
        self.assertEqual(len(rows), 25)
        self.assertTrue(all(row["passed"] for row in rows))
        self.assertEqual({row["target"] for row in rows}, {"pdk"})
        self.assertTrue(any(row["scenario"] == "backup-flash-restore-roundtrip" for row in rows))
        self.assertTrue(any(row["scenario"] == "full-controller-scope" for row in rows))
        inaccessible = next(row for row in rows if row["scenario"] == "bootloader-unreachable")
        self.assertFalse(inaccessible["recovered"])
        ack_loss = next(row for row in rows if row["scenario"] == "fault-lost-write-ack")
        self.assertEqual(sum(event["phase"] == "write" for event in ack_loss["failure_trace"]), 1)
