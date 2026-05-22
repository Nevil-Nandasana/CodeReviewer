"""
Dataset preparation — downloads Microsoft CodeReviewer from HuggingFace.
Filters to Python diffs, formats as chat messages for DeepSeek-Coder.
Output: data/train.jsonl, data/val.jsonl, data/test.jsonl
Runtime: ~30 min (downloads ~2GB)
"""
import json
import os
import random
from datasets import load_dataset

SYSTEM_PROMPT = (
    "You are an expert code reviewer specializing in Python security and best practices. "
    "Review the code change and identify bugs, security vulnerabilities, and quality issues. "
    'Respond with valid JSON only: {"comments": [{"line": <int>, "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", '
    '"category": "security|bug|quality|style", "title": "<title>", "explanation": "<explanation>", '
    '"suggestion": "<corrected code>", "owasp": "<OWASP or null>"}]}'
)

os.makedirs("data", exist_ok=True)

print("Downloading microsoft/CodeReviewer (~2GB, first run only)...")
dataset = load_dataset("microsoft/CodeReviewer", trust_remote_code=True)
print(f"Total examples: {len(dataset['train'])}")

def format_example(row) -> dict | None:
    diff = row.get("diff", "") or row.get("patch", "") or ""
    comment = row.get("msg", "") or row.get("comment", "") or ""
    if not diff or not comment or len(diff) > 3000:
        return None
    # Only Python diffs
    if "def " not in diff and "import " not in diff and ".py" not in diff:
        return None
    # Build a minimal JSON response from the human comment
    review_json = json.dumps({"comments": [
        {"line": 1, "severity": "MEDIUM", "category": "quality",
         "title": "Code review comment", "explanation": comment.strip(),
         "suggestion": "", "owasp": None}
    ]})
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Review this code change:\n\n<diff>\n{diff}\n</diff>"},
            {"role": "assistant", "content": review_json},
        ]
    }

examples = []
for row in dataset["train"]:
    formatted = format_example(row)
    if formatted:
        examples.append(formatted)

print(f"Python examples extracted: {len(examples)}")
random.shuffle(examples)

n_train = int(len(examples) * 0.9)
n_val = int(len(examples) * 0.05)

splits = {
    "train": examples[:n_train],
    "val": examples[n_train:n_train + n_val],
    "test": examples[n_train + n_val:],
}

for split, data in splits.items():
    path = f"data/{split}.jsonl"
    with open(path, "w") as f:
        for ex in data:
            f.write(json.dumps(ex) + "\n")
    print(f"Saved {len(data)} examples to {path}")

print("\nDataset preparation complete.")
print("Next: python data/augment_security.py")
