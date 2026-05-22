"""Subsample training data to N examples for overnight runs."""
import json, random, argparse

parser = argparse.ArgumentParser()
parser.add_argument("--n", type=int, default=10000)
args = parser.parse_args()

with open("data/train.jsonl") as f:
    all_data = [json.loads(line) for line in f]

security = [d for d in all_data if "CRITICAL" in str(d) or "sql_injection" in str(d).lower()]
other = [d for d in all_data if d not in security]

n_sec = min(len(security), args.n // 5)
n_other = min(args.n - n_sec, len(other))
sampled = security[:n_sec] + random.sample(other, n_other)
random.shuffle(sampled)

with open("data/train_small.jsonl", "w") as f:
    for ex in sampled:
        f.write(json.dumps(ex) + "\n")

print(f"Saved {len(sampled)} examples → data/train_small.jsonl")
print(f"  Security: {n_sec} | Other: {n_other}")
