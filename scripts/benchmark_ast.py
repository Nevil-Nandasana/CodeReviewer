"""
AST latency benchmark — measures extraction and scanning speed.
Target: AST extraction < 50ms, security scan < 10ms
Run: python scripts/benchmark_ast.py
"""
import sys
import os
import time
import statistics
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.ast_engine.extractor import ASTExtractor
from app.ast_engine.security_scanner import SecurityScanner

extractor = ASTExtractor()
scanner = SecurityScanner()

SAMPLE_CODE = '''
import os
import hashlib
import pickle

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)

def run_ping(host):
    os.system("ping " + host)

def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def load_cache(data):
    return pickle.loads(data)

def calculate_metrics(data_points):
    results = []
    for point in data_points:
        if point > 0:
            for sub in range(point):
                if sub % 2 == 0:
                    results.append(sub * point)
    return results

SECRET_KEY = "hardcoded-secret-value-12345"

def process_file(filename):
    return open("/uploads/" + filename).read()
''' * 5  # Simulate 500-line file

N = 100

# Benchmark AST extraction
ast_times = []
for _ in range(N):
    t0 = time.perf_counter()
    ctx = extractor.extract(SAMPLE_CODE, "python")
    ast_times.append((time.perf_counter() - t0) * 1000)

# Benchmark security scan
scan_times = []
for _ in range(N):
    ctx = extractor.extract(SAMPLE_CODE, "python")
    t0 = time.perf_counter()
    vulns = scanner.scan(ctx, SAMPLE_CODE)
    scan_times.append((time.perf_counter() - t0) * 1000)

print("=" * 55)
print(f"{'AST Benchmark':^55}")
print("=" * 55)
print(f"Code size       : {len(SAMPLE_CODE.splitlines())} lines")
print(f"Iterations      : {N}")
print()
print(f"{'AST Extraction (ms)':30}", end="")
print(f"mean={statistics.mean(ast_times):.2f}  p50={statistics.median(ast_times):.2f}  p95={sorted(ast_times)[int(N*0.95)]:.2f}")
print(f"{'Security Scan (ms)':30}", end="")
print(f"mean={statistics.mean(scan_times):.2f}  p50={statistics.median(scan_times):.2f}  p95={sorted(scan_times)[int(N*0.95)]:.2f}")
print()

ast_target = 50
scan_target = 10
ast_pass = statistics.mean(ast_times) < ast_target
scan_pass = statistics.mean(scan_times) < scan_target

print(f"AST target < {ast_target}ms  : {'✓ PASS' if ast_pass else '✗ FAIL'}")
print(f"Scan target < {scan_target}ms   : {'✓ PASS' if scan_pass else '✗ FAIL'}")
print(f"Vulnerabilities found: {len(vulns)}")
print("=" * 55)

sys.exit(0 if ast_pass and scan_pass else 1)
