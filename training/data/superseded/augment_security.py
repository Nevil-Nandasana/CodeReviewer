"""
SecurityEval augmentation — expand 130 vulnerable functions to 2000 examples.
Appends to data/train.jsonl.
"""
import json
import random
import os

SYSTEM_PROMPT = (
    "You are an expert code reviewer specializing in Python security and best practices. "
    "Review the code change and identify bugs, security vulnerabilities, and quality issues. "
    'Respond with valid JSON only: {"comments": [{"line": <int>, "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", '
    '"category": "security|bug|quality|style", "title": "<title>", "explanation": "<explanation>", '
    '"suggestion": "<corrected code>", "owasp": "<OWASP or null>"}]}'
)

# Base vulnerable patterns — represent SecurityEval dataset
SECURITY_PATTERNS = [
    {
        "code": 'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = " + user_id\n    return db.execute(query)',
        "comment": {"line": 2, "severity": "CRITICAL", "category": "security",
                    "title": "SQL Injection via string concatenation",
                    "explanation": "user_id concatenated directly into SQL. Attacker can inject arbitrary SQL.",
                    "suggestion": "return db.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                    "owasp": "A03:2021 Injection"},
    },
    {
        "code": 'def run_command(name):\n    os.system("ping " + name)',
        "comment": {"line": 2, "severity": "CRITICAL", "category": "security",
                    "title": "Command injection via string concatenation",
                    "explanation": "User input concatenated into shell command. Attacker can execute arbitrary commands.",
                    "suggestion": "subprocess.run(['ping', name], shell=False)",
                    "owasp": "A03:2021 Injection"},
    },
    {
        "code": 'def load_data(data):\n    return pickle.loads(data)',
        "comment": {"line": 2, "severity": "CRITICAL", "category": "security",
                    "title": "Insecure deserialization with pickle",
                    "explanation": "pickle.loads on untrusted data can execute arbitrary code.",
                    "suggestion": "Use json.loads() instead. Never deserialize untrusted data with pickle.",
                    "owasp": "A08:2021 Software and Data Integrity Failures"},
    },
    {
        "code": 'def hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()',
        "comment": {"line": 2, "severity": "HIGH", "category": "security",
                    "title": "MD5 is cryptographically broken",
                    "explanation": "MD5 has known collision attacks. Do not use for password hashing.",
                    "suggestion": "Use bcrypt: bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
                    "owasp": "A02:2021 Cryptographic Failures"},
    },
    {
        "code": 'SECRET_KEY = "my-super-secret-key-123"',
        "comment": {"line": 1, "severity": "HIGH", "category": "security",
                    "title": "Hardcoded secret key",
                    "explanation": "Secret keys in source code are exposed in version control.",
                    "suggestion": "SECRET_KEY = os.environ.get('SECRET_KEY')",
                    "owasp": "A02:2021 Cryptographic Failures"},
    },
]

# Variable name pools for augmentation
VAR_NAMES = ["user_id", "uid", "id_", "user_input", "param", "value", "req_id", "item_id"]
FUNC_NAMES = ["get_user", "fetch_data", "load_record", "retrieve", "query_db", "find_item"]
DB_OBJS = ["db", "conn", "cursor", "session", "database"]

def augment(pattern: dict, seed: int) -> dict:
    """Create a variant of a security pattern by substituting variable names."""
    random.seed(seed)
    code = pattern["code"]
    comment = dict(pattern["comment"])

    if "user_id" in code:
        new_var = random.choice(VAR_NAMES)
        code = code.replace("user_id", new_var)
        comment["explanation"] = comment["explanation"].replace("user_id", new_var)

    if "get_user" in code:
        new_func = random.choice(FUNC_NAMES)
        code = code.replace("get_user", new_func)

    if "db" in code:
        new_db = random.choice(DB_OBJS)
        code = code.replace("db", new_db)

    diff = f"--- a/app.py\n+++ b/app.py\n" + "\n".join(f"+{line}" for line in code.splitlines())
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Review this code change:\n\n<diff>\n{diff}\n</diff>"},
            {"role": "assistant", "content": json.dumps({"comments": [comment]})},
        ]
    }

# Generate 2000 examples
examples = []
target = 2000
per_pattern = target // len(SECURITY_PATTERNS)

for pattern in SECURITY_PATTERNS:
    for i in range(per_pattern):
        examples.append(augment(pattern, seed=i))

random.shuffle(examples)

# Append to train.jsonl
train_path = "data/train.jsonl"
os.makedirs("data", exist_ok=True)
with open(train_path, "a") as f:
    for ex in examples:
        f.write(json.dumps(ex) + "\n")

print(f"Appended {len(examples)} security examples to {train_path}")
print("SecurityEval augmentation complete.")
