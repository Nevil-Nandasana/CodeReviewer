"""Validate JSONL dataset format before training."""
import json, sys

errors = 0
for path in ["data/train.jsonl", "data/val.jsonl"]:
    try:
        with open(path) as f:
            for i, line in enumerate(f, 1):
                obj = json.loads(line)
                assert "messages" in obj, f"Missing 'messages' key at line {i}"
                assert len(obj["messages"]) >= 2, f"Need >= 2 messages at line {i}"
                roles = [m["role"] for m in obj["messages"]]
                assert "user" in roles and "assistant" in roles, f"Missing user/assistant at line {i}"
        print(f"✓ {path}: format valid")
    except FileNotFoundError:
        print(f"✗ {path}: not found (run prepare_dataset.py first)")
        errors += 1
    except (json.JSONDecodeError, AssertionError) as e:
        print(f"✗ {path}: {e}")
        errors += 1

sys.exit(errors)
