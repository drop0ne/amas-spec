import unittest

from evaluation.trust_boundary import (
    LocalTrustBoundary,
    ProcessTrustBoundary,
    TrustBoundaryError,
    TrustBoundaryUnavailable,
)

STATE_A = "a" * 64
STATE_B = "b" * 64
EXECUTION = "c" * 64
ACTION = "d" * 64


class LocalTrustBoundaryTests(unittest.TestCase):
    def test_checkpoint_anchor_is_immutable(self):
        service = LocalTrustBoundary(identity_secret=b"local-test-secret")
        service.anchor_checkpoint("cp-1", STATE_A, 3)
        self.assertTrue(service.checkpoint_matches("cp-1", STATE_A, 3))
        with self.assertRaises(TrustBoundaryError):
            service.anchor_checkpoint("cp-1", STATE_B, 3)
        self.assertTrue(service.checkpoint_matches("cp-1", STATE_A, 3))

    def test_completion_transition_is_forward_only(self):
        service = LocalTrustBoundary(identity_secret=b"local-test-secret")
        service.record_completion(EXECUTION, ACTION, "STARTED")
        service.record_completion(EXECUTION, ACTION, "OUTCOME_UNKNOWN")
        final = service.record_completion(EXECUTION, ACTION, "EFFECT_CONFIRMED")
        self.assertEqual(final["state"], "EFFECT_CONFIRMED")
        with self.assertRaises(TrustBoundaryError):
            service.record_completion(EXECUTION, ACTION, "SUCCEEDED")

    def test_revocation_and_identity(self):
        service = LocalTrustBoundary(identity_secret=b"local-test-secret")
        self.assertFalse(service.is_revoked("L1"))
        service.revoke("L1")
        self.assertTrue(service.is_revoked("L1"))
        identity = service.issue_identity("agent")
        self.assertTrue(service.verify_identity("agent", identity["token"]))
        self.assertFalse(service.verify_identity("other", identity["token"]))


class ProcessTrustBoundaryTests(unittest.TestCase):
    def test_separate_process_owns_checkpoint_revocation_completion_and_identity(self):
        with ProcessTrustBoundary() as service:
            anchored = service.anchor_checkpoint("cp-1", STATE_A, 7)
            anchored["state_hash"] = STATE_B
            self.assertTrue(service.checkpoint_matches("cp-1", STATE_A, 7))
            self.assertFalse(service.checkpoint_matches("cp-1", STATE_B, 7))

            service.revoke("L1")
            self.assertTrue(service.is_revoked("L1"))

            service.record_completion(EXECUTION, ACTION, "STARTED")
            service.record_completion(EXECUTION, ACTION, "OUTCOME_UNKNOWN")
            record = service.record_completion(EXECUTION, ACTION, "NO_EFFECT_CONFIRMED")
            self.assertEqual(record["state"], "NO_EFFECT_CONFIRMED")
            self.assertEqual(service.get_completion(EXECUTION)["state"], "NO_EFFECT_CONFIRMED")

            identity = service.issue_identity("agent")
            self.assertTrue(service.verify_identity("agent", identity["token"]))
            self.assertFalse(service.verify_identity("other", identity["token"]))

    def test_process_unavailability_is_explicit_fail_closed_signal(self):
        service = ProcessTrustBoundary()
        try:
            service.terminate_for_test()
            with self.assertRaises(TrustBoundaryUnavailable):
                service.is_revoked("L1")
        finally:
            service.close(force=True)


if __name__ == "__main__":
    unittest.main()
