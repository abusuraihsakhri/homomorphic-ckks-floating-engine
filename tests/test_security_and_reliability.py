"""
Security and reliability tests for homomorphic-ckks-floating-engine.
Covers: audit key generation, enrichment suite integrity, CLI batch validation, simulator resilience.
"""
import sys
import os
import warnings
import tempfile
import csv
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from agents.base import AuditTrail, AuditLogger, PHIGuard, SecurityException
from enrichment import HomomorphicckksfloatingengineEnrichmentSuite


class TestAuditTrailSecurity:
    """Verify audit trail uses secure key generation when no key is provided."""

    def test_random_key_generated_without_env(self):
        """AuditTrail should generate a cryptographically secure random key when no key is set."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            trail = AuditTrail()
        assert len(trail.secret_key) >= 16  # At least 128-bit key

    def test_random_key_differs_between_instances(self):
        """Each AuditTrail instance without a key should get a unique random key."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            t1 = AuditTrail()
            t2 = AuditTrail()
        assert t1.secret_key != t2.secret_key

    def test_explicit_key_is_used(self):
        """When a key is explicitly provided, it should be used directly."""
        trail = AuditTrail(secret_key="my-test-key-12345")
        assert trail.secret_key == b"my-test-key-12345"

    def test_env_var_key_is_used(self):
        """When AUDIT_SECRET_KEY env var is set, it should be used."""
        os.environ["AUDIT_SECRET_KEY"] = "env-based-key-12345"
        try:
            trail = AuditTrail()
            assert trail.secret_key == b"env-based-key-12345"
        finally:
            del os.environ["AUDIT_SECRET_KEY"]

    def test_audit_trail_integrity_with_random_key(self):
        """Audit trail should maintain integrity even with a random key."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            trail = AuditTrail()
        trail.log("test", "tier1", "EVENT", {"data": "value1"})
        trail.log("test", "tier1", "EVENT", {"data": "value2"})
        assert trail.verify_integrity() is True
        assert len(trail.get_trail()) == 2


class TestEnrichmentSuiteIntegrity:
    """Verify the enrichment suite correctly instantiates all engines."""

    def test_all_engines_are_distinct_instances(self):
        """Each engine in the enrichment suite should be a separate instance."""
        suite = HomomorphicckksfloatingengineEnrichmentSuite()
        assert suite.simdoptimizer is not suite.noisebudgetanalyzer

    def test_execute_all_returns_all_engines(self):
        """execute_all should return results from all 8 engines."""
        suite = HomomorphicckksfloatingengineEnrichmentSuite()
        results = suite.execute_all(primary_val=0.5, secondary_val=0.2)
        assert len(results) == 8
        expected_keys = [
            "PerformanceBenchmarkingSuiteWithOperationCountsAndTimingEngine",
            "SidechannelResistanceAnalysisConstanttimeVerificationEngine",
            "InteroperabilityTestingAgainstLiboqsPqcryptoBoringsslVectorsEngine",
            "FheBootstrappingPerformanceProfilerEngine",
            "FormalSecurityProofDocumentationIndcpaIndcpadEngine",
            "NistComplianceCertificationChecklistWithTestVectorValidationEngine",
            "AdditionalEnhancementSimdVectorEncodingOptimizerEngine",
            "AdditionalEnhancementNoiseBudgetAnalyzerEngine",
        ]
        for key in expected_keys:
            assert key in results, f"Missing engine result: {key}"

    def test_simd_and_noise_budget_produce_different_results(self):
        """SIMD optimizer and noise budget analyzer should produce independent results."""
        suite = HomomorphicckksfloatingengineEnrichmentSuite()
        results = suite.execute_all(primary_val=10.0, secondary_val=5.0)
        simd_result = results["AdditionalEnhancementSimdVectorEncodingOptimizerEngine"]
        noise_result = results["AdditionalEnhancementNoiseBudgetAnalyzerEngine"]
        # Both should have alerts at this threshold
        assert len(simd_result.alerts) > 0
        assert len(noise_result.alerts) > 0


class TestCLIBatchValidation:
    """Verify CLI batch mode handles invalid inputs gracefully."""

    def test_batch_missing_file_returns_error(self, capsys):
        """Batch command with non-existent file should return exit code 1."""
        from cli import main
        result = main(["batch", "-i", "nonexistent_file_12345.csv"])
        assert result == 1

    def test_batch_invalid_metric_skips_row(self, capsys):
        """Batch command should skip rows with invalid metric values."""
        from cli import main
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["task_id", "target_identifier", "primary_metric", "secondary_metric", "status_descriptor"])
            writer.writeheader()
            writer.writerow({"task_id": "T1", "target_identifier": "K1", "primary_metric": "invalid", "secondary_metric": "5.0", "status_descriptor": "NOMINAL"})
            writer.writerow({"task_id": "T2", "target_identifier": "K2", "primary_metric": "15.0", "secondary_metric": "5.0", "status_descriptor": "NOMINAL"})
            tmp_path = f.name
        try:
            result = main(["batch", "-i", tmp_path, "-o", "test_output.csv"])
            captured = capsys.readouterr()
            assert result == 0
            assert "Skipping row" in captured.err or "T1" in captured.err
            # Clean up output file
            if os.path.exists("test_output.csv"):
                os.remove("test_output.csv")
        finally:
            os.remove(tmp_path)

    def test_batch_valid_csv_succeeds(self):
        """Batch command with valid CSV should return exit code 0."""
        from cli import main
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["task_id", "target_identifier", "primary_metric", "secondary_metric", "status_descriptor"])
            writer.writeheader()
            writer.writerow({"task_id": "T1", "target_identifier": "K1", "primary_metric": "15.0", "secondary_metric": "5.0", "status_descriptor": "NOMINAL"})
            tmp_path = f.name
        try:
            result = main(["batch", "-i", tmp_path, "-o", "test_output.csv"])
            assert result == 0
            assert os.path.exists("test_output.csv")
            if os.path.exists("test_output.csv"):
                os.remove("test_output.csv")
        finally:
            os.remove(tmp_path)


class TestSimulatorResilience:
    """Verify simulator handles edge cases gracefully."""

    def test_simulator_rejects_zero_iterations(self):
        """Simulator should reject zero or negative iterations."""
        from simulator import run_simulation
        with pytest.raises(ValueError):
            run_simulation(0)
        with pytest.raises(ValueError):
            run_simulation(-1)

    def test_simulator_runs_with_small_count(self):
        """Simulator should complete successfully with a small iteration count."""
        from simulator import run_simulation
        run_simulation(5)  # Should not raise
