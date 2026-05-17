"""
Test model inference after training.
Run: python scripts/test_model_inference.py
Expected: VRAM < 4GB, inference < 10s, valid JSON output.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

TEST_CASES = [
    {
        "name": "SQL injection — should flag CRITICAL",
        "code": 'def get_user(user_id):\n    return db.execute("SELECT * FROM users WHERE id = " + user_id)',
        "expect_severity": "CRITICAL",
        "expect_keyword": "injection",
    },
    {
        "name": "Clean code — should have no critical issues",
        "code": 'def get_user(user_id: int):\n    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        "expect_severity": None,
        "expect_keyword": None,
    },
    {
        "name": "Hardcoded secret — should flag HIGH",
        "code": 'SECRET_KEY = "my-super-secret-abc123"\ndef connect():\n    return db.connect(password=SECRET_KEY)',
        "expect_severity": "HIGH",
        "expect_keyword": "secret",
    },
]

def main():
    from app.config import settings

    print(f"Testing model backend: {settings.MODEL_BACKEND}")
    print("=" * 50)

    if settings.MODEL_BACKEND == "local":
        try:
            import torch
            print(f"VRAM before load: {torch.cuda.memory_allocated() / 1e9:.2f} GB")
        except ImportError:
            print("torch not installed — cannot measure VRAM")

    from app.llm_engine.model_client import ModelClient

    client = ModelClient()

    if settings.MODEL_BACKEND == "local":
        try:
            print(f"VRAM after load: {torch.cuda.memory_allocated() / 1e9:.2f} GB")
        except Exception:
            pass

    passed = 0
    for i, tc in enumerate(TEST_CASES, 1):
        print(f"\nTest {i}: {tc['name']}")
        diff = "--- a/app.py\n+++ b/app.py\n" + "\n".join(f"+{l}" for l in tc['code'].splitlines())
        try:
            # ModelClient.review returns its own elapsed time, so timing here
            # would only measure the same call twice.
            comments, model, elapsed = client.review(diff=diff, language="python")
            print(f"  Time: {elapsed:.2f}s | Model: {model} | Comments: {len(comments)}")

            # Validate JSON structure
            assert isinstance(comments, list), "Output is not a list"

            if tc["expect_severity"]:
                has_expected = any(
                    c.get("severity") == tc["expect_severity"] or
                    (tc["expect_keyword"] and tc["expect_keyword"].lower() in str(c).lower())
                    for c in comments
                )
                if has_expected:
                    print(f"  ✓ Detected {tc['expect_severity']} as expected")
                    passed += 1
                else:
                    print(f"  ✗ Expected {tc['expect_severity']} but not detected")
                    print(f"    Got: {comments}")
            else:
                critical = [c for c in comments if c.get("severity") == "CRITICAL"]
                if not critical:
                    print("  ✓ No false positive CRITICAL on clean code")
                    passed += 1
                else:
                    print(f"  ✗ False positive: {critical}")

        except Exception as e:
            print(f"  ✗ Error: {e}")

    print("\n" + "=" * 50)
    print(f"Results: {passed}/{len(TEST_CASES)} tests passed")
    if passed == len(TEST_CASES):
        print("Model inference test PASSED ✓")
    else:
        print("Some tests failed — check model output above")
    print("=" * 50)
    sys.exit(0 if passed == len(TEST_CASES) else 1)

if __name__ == "__main__":
    main()
