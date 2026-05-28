# CodeReviewer - AI Code Review and Security Intelligence Platform

CodeReviewer automatically reviews GitHub pull requests for security and code-quality problems. It combines a custom static-analysis engine with a language model, posts comments on the changed lines, stores the results, and shows them in a React dashboard.

The most important part of this project is not only the AI model. It is the evaluation system used to measure whether the reviewer is accurate, useful, and quiet on safe code.

## Interview answer: "Tell me about your project"

> I built CodeReviewer, an end-to-end AI code review and security platform. When a pull request is opened or updated, GitHub sends a webhook to my FastAPI backend. I verify the webhook using HMAC-SHA256 and send the review to a Celery worker through Redis, so GitHub gets a fast response while the analysis runs in the background.
>
> The worker downloads the pull-request diff and reviews only the changed code. My custom Python AST engine tracks untrusted data from sources, such as request parameters, to dangerous sinks, such as SQL queries, shell commands, file operations, and `eval`. It applies 11 security rules. The same diff and static-analysis context are also sent to either a local model or OpenAI, and the model returns structured JSON findings. I validate the output, keep comments only on changed lines, store everything in PostgreSQL, and post inline comments back to GitHub. I also built a React dashboard and a VS Code extension.
>
> To measure the system honestly, I built a 240-case benchmark with vulnerable examples, matched safe versions, and difficult but safe distractors. The rule engine achieved 81.1 F1 and did not flag any of the 120 clean control cases in the test split. The evaluation also showed that the base model found some vulnerability families unseen by the rules, but produced too many false alarms. This taught me that rules and LLMs have different strengths and should eventually be combined by taking useful findings from both, instead of asking the model to reject rule findings.

## What problem does CodeReviewer solve?

Manual pull-request review can be slow and reviewers may miss security bugs. A simple keyword scanner is fast but does not understand how data moves through code. A language model understands more patterns but may invent issues.

CodeReviewer uses both approaches:

- Static rules give fast and predictable findings.
- Taint analysis follows untrusted data through variables and expressions.
- An LLM can notice patterns that were not written as rules.
- A benchmark measures accuracy and false alarms instead of assuming the system works.

## High-level architecture

```text
Developer opens or updates a GitHub pull request
                    |
                    v
        GitHub webhook -> FastAPI API
        HMAC-SHA256 signature verification
                    |
                    v
          Redis queue -> Celery worker
                    |
                    v
              ReviewPipeline
        +-----------+-------------+
        |                         |
  Diff + AST analysis       LLM review
  + security rules          local or OpenAI
        |                         |
        +-----------+-------------+
                    |
       validate JSON and changed lines
                    |
        +-----------+-------------+
        |                         |
 PostgreSQL database     GitHub inline comments
        |
 React dashboard / REST API / VS Code extension
```

## How one pull-request review works

1. GitHub sends a `pull_request` event for `opened`, `synchronize`, or `reopened`.
2. The webhook body is checked with HMAC-SHA256 and `hmac.compare_digest`.
3. FastAPI adds a Celery task to Redis and returns immediately.
4. The worker uses a short-lived GitHub App installation token to fetch the PR diff.
5. Diffs larger than 500 KB are skipped. At most 50 supported files are reviewed.
6. `DiffParser` separates files and hunks and records the exact new-file line numbers.
7. For every file, the pipeline extracts the added code plus nearby context.
8. The AST engine finds functions, calls, imports, complexity, and source-to-sink data flows.
9. The security scanner applies 11 rules to the extracted structure and code.
10. The LLM receives numbered diff lines, AST context, and rule findings as claims to verify.
11. `ResponseParser` recovers and validates the JSON returned by the model.
12. Any comment outside the changed lines is removed.
13. Review comments, high/critical vulnerabilities, and quality metrics are stored in PostgreSQL.
14. Inline comments and a summary are posted on GitHub. Stable fingerprints prevent duplicate inline findings.

## Main features and their implementation

| Feature | How it is implemented |
|---|---|
| GitHub automation | A GitHub App sends PR webhooks to `POST /api/v1/webhook/github`. PyGithub fetches diffs and posts review comments. |
| Secure webhooks | The backend recreates the HMAC-SHA256 signature using the webhook secret and compares it in constant time. |
| Background processing | Celery uses Redis as its broker. A task retries transient failures twice but does not retry permanent input errors. |
| Diff-aware comments | The custom unified-diff parser maps added lines to their real new-file line numbers. Model comments outside those lines are discarded. |
| Static security analysis | Python's `ast` module builds structure and performs source-to-sink taint tracking. Tree-sitter/regex paths provide fallbacks for other inputs. |
| AI review | `ModelClient` selects a configured local model or OpenAI. Prompt v2 requests strict JSON and explicitly allows an empty result for safe code. |
| Robust model output | The parser tries direct JSON, removes Markdown fences, extracts a balanced object, and repairs simple truncation. Invalid findings are dropped safely. |
| Caching | The SHA-256 hash of a diff forms a Redis cache key with a one-hour default TTL. |
| Inline deduplication | A hash of file, line, severity, and title is embedded in each GitHub comment and checked before reposting. |
| Code quality | The analyzer records LOC, comment ratio, function length, cyclomatic complexity, and a quality score from 0 to 100. |
| Authentication | Users register or log in with a bcrypt password hash. Protected API calls use an HS256 JWT, which expires after 24 hours by default. |
| Dashboard | React Query loads reviews, vulnerabilities, OWASP counts, file heatmaps, quality trends, and repository statistics from FastAPI. |
| VS Code extension | It sends the current file to `/api/v1/reviews/trigger` and highlights reported lines by severity. It can review manually or on save. |
| Monitoring | Middleware produces structured JSON logs and Prometheus request metrics. Docker Compose includes Prometheus and Grafana. |

## How the security engine works

### AST and taint tracking

An AST, or Abstract Syntax Tree, represents code as programming structures instead of plain text. CodeReviewer uses Python's built-in AST parser for its most precise analysis.

Taint tracking follows untrusted data through three stages:

```text
Source                         Propagation                    Sink
request.args["name"] -> variable / f-string / method -> cursor.execute(query)
```

- **Sources:** request query/body/form/header values, `input()`, `read()`, and `recv()`.
- **Propagation:** assignments, subscripts, string concatenation, f-strings, `format`, `join`, `replace`, and similar operations.
- **Sanitizers:** operations such as `int`, `escape`, `secure_filename`, and `literal_eval` stop taint.
- **Sinks:** SQL execution, shell processes, file access, dynamic code execution, deserialization, and network calls.

The analysis is inside one function and is flow-insensitive. It makes two passes to find flows through assignments and branches. This is fast and useful for review-sized code, but it is not a complete whole-program security proof.

### The 11 implemented rules

| Vulnerability | CWE | Basic detection idea |
|---|---|---|
| SQL injection | CWE-89 | Tainted or interpolated data reaches a SQL execution call. |
| Command injection | CWE-78 | Tainted data reaches a shell command; safe argument-list calls are excluded. |
| Code injection | CWE-94 | Tainted data reaches `eval`, `exec`, `compile`, or similar calls. |
| Cross-site scripting | CWE-79 | Code bypasses normal HTML escaping. |
| Hardcoded credentials | CWE-798 | Secret-like variables contain long literal values. |
| Insecure deserialization | CWE-502 | Unsafe pickle, YAML, or marshal loading is used. |
| Path traversal | CWE-22 | Request-controlled paths reach file access without containment checks. |
| Weak cryptography | CWE-327 | MD5 or SHA-1 is used as a security primitive. |
| Disabled certificate validation | CWE-295 | TLS verification or hostname checking is disabled. |
| Missing authentication | CWE-306 | An administrative state-changing route has no known auth decorator. |
| Error information exposure | CWE-209 | A web route returns exception or traceback details to the client. |

SSRF, XXE, weak randomness, and unsafe file permissions intentionally have no rules. They are held out in the benchmark to test whether a model can find a new bug family.

## AI model and fine-tuning

The training pipeline fine-tunes `Qwen/Qwen2.5-Coder-1.5B-Instruct` using QLoRA:

- The base weights are loaded in 4-bit NF4 format.
- LoRA rank is 32, alpha is 64, and dropout is 0.05.
- Roughly 37 million adapter parameters are trained instead of updating the full model.
- The recorded run used 1,729 training and 309 validation examples.
- About half the examples are safe and teach the model to return `{"comments": []}`.
- Only answer tokens contribute to the loss; prompt tokens are masked with `-100`.
- Related template families stay together in train or validation to reduce data leakage.
- Overlong samples are dropped instead of truncated, because a cut JSON answer would teach invalid output.

The local benchmark runner uses the model's own chat template and deterministic generation. The production serving client supports a local model path or OpenAI through configuration.

## Evaluation: the strongest part of the project

The benchmark has 240 synthetic cases:

| Case type | Count | Purpose |
|---|---:|---|
| Vulnerable programs | 95 | Measure whether real bugs are found. |
| Matched safe twins | 95 | Same idea with the vulnerable line fixed; measure discrimination. |
| Safe distractors | 50 | Safe code that looks suspicious; measure false alarms. |

The test split contains 200 cases: 80 vulnerable, 80 safe twins, and 40 distractors. The separate dev split contains 40 cases and is used for tuning and checkpoint selection.

Scoring checks both the line and the CWE. Matching is one-to-one, so duplicate predictions cannot all count as correct. Reported metrics include precision, recall, F1, clean-code flag rate, line accuracy, severity error, JSON validity, latency, and cost.

The 95% confidence intervals resample whole template families. Variants from one template are very similar, so treating them as independent examples would make the results look more certain than they are.

### Recorded test results

| System | Precision | Recall | F1 | Clean control cases flagged |
|---|---:|---:|---:|---:|
| Rules only | **88.2%** | **75.0%** | **81.1%** | **0.0%** |
| Chained hybrid: rules -> fine-tuned LLM | 59.5% | 31.2% | 41.0% | 2.5% |
| Base Qwen v2 | 14.2% | 36.2% | 20.4% | 93.3% |
| Fine-tuned Qwen v2 | 42.1% | 10.0% | 16.2% | 2.5% |

Important interpretation:

- The rule engine is currently the strongest complete reviewer.
- The base model found 8 of 20 cases from the four held-out families; the rules and fine-tuned model found 0.
- The base model is not usable alone because it flags almost every clean control case.
- Fine-tuning greatly reduced false alarms but also removed held-out generalization.
- The current chained hybrid asks the LLM to confirm rules and loses correct rule findings. A better future design is to union carefully filtered rule and model findings.

### A useful training lesson

Validation loss selected checkpoint 50, with loss `0.589`, but its dev F1 was only `20.0`. Checkpoint 200 had a worse validation loss of `1.033` but a much better dev F1 of `41.7`.

This happened because about half the target answers are empty. A model can reduce token loss by staying quiet while becoming worse at finding vulnerabilities. The project therefore includes `evaluation/select_checkpoint.py` to compare checkpoints using benchmark F1 on the dev split, not the test split.

## Data stored in PostgreSQL

| Entity | What it stores |
|---|---|
| `User` | Account, password hash, GitHub identity, and admin flag. |
| `Repository` | GitHub repository, installation ID, owner, and review settings. |
| `PullRequest` | PR number, branches, author, status, and change statistics. |
| `Review` | Run status, model, severity counts, timings, and diff hash. |
| `ReviewComment` | File, line, severity, explanation, suggestion, and false-positive/resolved flags. |
| `Vulnerability` | High/critical security findings and their resolution status. |
| `QualityMetric` | Per-file complexity, LOC, comment ratio, function size, and score. |

Alembic manages schema migrations. SQLAlchemy provides the ORM and database sessions.

## API and user interfaces

| Area | Main routes or screens |
|---|---|
| Auth | Register, login, refresh token, and current user. |
| Reviews | List reviews/PRs, read findings, mark false positives, and review a VS Code snippet. |
| Repositories | Create, list, update, disable, and view repository statistics. |
| Security | Vulnerabilities, summary, OWASP breakdown, file heatmap, and trends. |
| Quality | Metrics, trends, complex files, and common issues. |
| Analytics | Dashboard totals, recent activity, and reviews per day. |
| Operations | `/health`, `/metrics`, `/docs`, and model status. |

The React application has pages for login, dashboard, PR reviews, security, code quality, and repositories. The API client automatically adds the JWT and logs the user out after a `401` response.

## Technology stack

- **Backend:** Python, FastAPI, SQLAlchemy 2, Alembic, Celery, Redis, PostgreSQL.
- **Analysis:** Python `ast`, tree-sitter, custom taint tracking, custom security rules.
- **AI/ML:** Qwen2.5-Coder-1.5B, Transformers, PEFT/QLoRA, bitsandbytes, OpenAI SDK.
- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, React Query, Zustand, Recharts.
- **Integrations:** GitHub App, PyGithub, VS Code extension.
- **Operations:** Docker Compose, Prometheus, Grafana, structlog, pytest.

## Important folders

```text
backend/app/api/                 REST endpoints
backend/app/ast_engine/          AST extraction, taint tracking, rules, quality
backend/app/github_integration/  webhooks, GitHub client, diff parser, comments
backend/app/llm_engine/          prompts, model clients, response parser
backend/app/review_pipeline/     end-to-end review orchestration
backend/app/tasks/               Celery configuration and review task
backend/app/models/              SQLAlchemy database models
frontend/src/                    React dashboard
vscode-extension/src/            VS Code integration
training/                        dataset creation and QLoRA training
evaluation/                      benchmark, runners, matching, metrics, reports
infrastructure/monitoring/       Prometheus and Grafana configuration
```

## Run the project

### Full Docker stack

```powershell
Copy-Item .env.example backend/.env
# Edit backend/.env and replace every placeholder secret.
docker compose up -d
```

On macOS/Linux, use `cp .env.example backend/.env` instead. The main services are:

- Frontend: `http://localhost:3000`
- API and Swagger: `http://localhost:8000` and `http://localhost:8000/docs`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`

If `MODEL_BACKEND=openai`, code diffs are sent to OpenAI. Local mode keeps model inference on the configured machine but requires the local model files and suitable GPU setup.

### Reproduce the rule benchmark

```bash
python -m evaluation.run_eval --systems rules-only --split test
```

This needs no API key, Docker, or GPU. Results are written under `evaluation/results/`.

### Run checks

```bash
cd backend
python -m pytest tests -q
cd ..
python -m pytest evaluation/tests -q
cd frontend
npm run build
```

Current verification: **87 backend tests and 36 evaluation tests pass**. The frontend TypeScript check and production Vite build also pass.

## Common interview questions

### Why did you use both static analysis and an LLM?

Static analysis is fast, explainable, and precise for known patterns. An LLM can recognize unfamiliar patterns but may create false alarms. The benchmark proved this trade-off: rules had the best F1, while the base model was the only system to find some held-out bug families.

### Why use an AST instead of regex for everything?

Regex sees text, but an AST understands calls, assignments, parameters, and expressions. That allows CodeReviewer to follow a value from `request.args` into a variable, through an f-string, and finally into `execute()`.

### Why is the webhook asynchronous?

Model inference and repository analysis can take seconds. The webhook verifies and queues the job quickly, while Celery performs the slow work separately. This prevents GitHub timeouts and makes retries possible.

### How do you control false positives?

I use safe twins and distractors in the benchmark, exclude known safe forms in rules, tell the model that an empty answer is valid, validate the output, and restrict comments to changed lines. False-positive rate is reported beside recall and F1.

### How do you secure the system?

Webhook signatures use HMAC-SHA256 and constant-time comparison. GitHub access uses short-lived installation tokens. API passwords are hashed with bcrypt, protected routes use JWTs, secrets come from environment variables, and production startup refuses known placeholder secrets.

### How do you avoid duplicate comments?

Each inline finding gets a stable fingerprint based on file, line, severity, and title. CodeReviewer reads existing markers from the PR before posting. LLM responses are also cached by the SHA-256 hash of the diff.

### What was the biggest technical lesson?

The proxy metric was misleading. Validation loss preferred a checkpoint that stayed quiet, while benchmark F1 preferred a later checkpoint that found more bugs. Task-specific evaluation was more useful than token-level loss.

### How would you scale it?

Run more API workers, share rate limiting and caching through Redis, add Celery queues by repository or model type, use CPU workers for static analysis and GPU workers for model inference, and process independent files in parallel while keeping GitHub rate limits under control.

### What would you improve next?

I would add real CVE-derived diffs, combine rule and base-model findings with a measured union/dedup strategy, strengthen non-Python data-flow analysis, complete multi-tenant authorization, and add end-to-end GitHub integration tests.

## Honest current limitations

- The benchmark is synthetic. Held-out families reduce memorization risk but do not replace testing on real projects and CVEs.
- Precise taint tracking is strongest for complete Python code. Non-Python and incomplete-code fallback analysis is much shallower.
- The implemented production flow chains rule findings through the LLM, although the evaluation shows that this loses recall. The measured union design is future work.
- Repository CRUD has ownership checks, but several review, security, quality, and analytics list endpoints are not yet fully scoped per user. This is not production-grade multi-tenancy.
- The GitHub OAuth callback is a placeholder; normal email/password JWT login is implemented.
- Redis support exists in the rate-limit middleware, but the current FastAPI wiring uses its in-process fallback. A shared Redis client should be injected for multi-worker production use.
- Inline findings are deduplicated, but the PR summary does not yet use the same fingerprint mechanism.
- The production local-model wrapper still contains old DeepSeek labels and manual chat formatting, while the recorded training/evaluation pipeline uses Qwen's chat template. These paths should be aligned before deployment.

---

**One-line resume version:** Built an AI-assisted GitHub code-review platform using FastAPI, Python AST taint analysis, Celery, Redis, PostgreSQL, React, and QLoRA, and evaluated it with a 240-case security benchmark focused on both bug detection and false-positive control.
