.PHONY: help up down dev backend frontend celery migrate seed test lint build clean \
        eval eval-rules eval-base eval-ft score score-dev select-checkpoint \
        build-data train merge-model check-config benchmark

# ── Default ─────────────────────────────────────────────────────────────────────
help:
	@echo "CodeReviewer — AI Code Review Platform"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "  up          Start all Docker services"
	@echo "  down        Stop all Docker services"
	@echo "  dev         Start dev stack (postgres + redis only)"
	@echo "  backend     Run FastAPI backend locally"
	@echo "  celery      Run Celery worker locally"
	@echo "  frontend    Run React frontend locally"
	@echo "  migrate     Run Alembic migrations"
	@echo "  seed        Seed demo data"
	@echo "  test        Run all backend tests"
	@echo "  lint        Run linters"
	@echo "  build       Build Docker images"
	@echo "  clean       Remove all containers and volumes"
	@echo ""
	@echo "Evaluation (no API key, no Docker needed):"
	@echo "  eval          Run the rule baseline and score it"
	@echo "  eval-base     Run the local base model, prompts v1 and v2"
	@echo "  eval-ft       Run the fine-tune + hybrid  (ADAPTER=path)"
	@echo "  score         Re-score recorded results without re-running models"
	@echo "  score-dev     Re-validate on the untouched dev split"
	@echo "  select-checkpoint  Rank checkpoints by dev F1, not by eval_loss"
	@echo ""
	@echo "Training:"
	@echo "  build-data    Regenerate the SFT dataset (grouped family split)"
	@echo "  train         QLoRA fine-tune          (RUN_NAME=name)"
	@echo "  merge-model   Merge the LoRA adapter into the base weights"
	@echo ""
	@echo "  check-config  Report unknown .env keys and placeholder secrets"
	@echo "  benchmark     AST engine throughput"

# ── Docker ──────────────────────────────────────────────────────────────────────
up:
	docker compose up -d

down:
	docker compose down

dev:
	docker compose up -d postgres redis
	@echo "Postgres and Redis are up. Run 'make migrate' then 'make backend'"

build:
	docker compose build

clean:
	docker compose down -v
	docker system prune -f

logs:
	docker compose logs -f

# ── Local Development ────────────────────────────────────────────────────────────
migrate:
	cd backend && alembic upgrade head

migrate-down:
	cd backend && alembic downgrade -1

backend:
	cd backend && uvicorn app.main:app --reload --port 8000

celery:
	cd backend && celery -A app.tasks.celery_app worker --loglevel=info --concurrency=2

frontend:
	cd frontend && npm run dev

# ── Database ─────────────────────────────────────────────────────────────────────
seed:
	cd backend && python ../scripts/seed_demo_repos.py

# ── Testing ──────────────────────────────────────────────────────────────────────
# Two suites with different roots: backend tests import `app.*` from backend/,
# harness tests import `evaluation.*` from here.
test: test-backend test-eval

test-backend:
	cd backend && pytest tests/ -q

test-eval:
	pytest evaluation/tests -q

test-cov:
	cd backend && pytest tests/ --cov=app --cov-report=term-missing

test-ast:
	cd backend && pytest tests/test_ast_engine/ -v

test-api:
	cd backend && pytest tests/test_api/ -v

test-regressions:
	cd backend && pytest tests/test_regressions.py -v

# ── Linting ──────────────────────────────────────────────────────────────────────
lint:
	cd backend && ruff check app/ tests/
	cd frontend && npm run lint

format:
	cd backend && ruff format app/ tests/
	cd frontend && npm run format

# ── Evaluation ───────────────────────────────────────────────────────────────────
# Inference and scoring are separate on purpose: changing a metric re-scores
# recorded output without re-running any model. Runs resume by default; pass
# FORCE=--force to start over.
FORCE ?=
SPLIT ?= test

eval: eval-rules score

eval-rules:
	python -m evaluation.run_eval --systems rules-only --split $(SPLIT) $(FORCE) --no-score

eval-base:
	python -m evaluation.run_eval --systems local:Qwen/Qwen2.5-Coder-1.5B-Instruct:v1,local:Qwen/Qwen2.5-Coder-1.5B-Instruct:v2 --split $(SPLIT) $(FORCE) --no-score

eval-ft:
	python -m evaluation.run_eval --systems local-ft:$(ADAPTER):v2,hybrid:local-ft:$(ADAPTER):v2 --split $(SPLIT) $(FORCE) --no-score

score:
	python -m evaluation.score --split $(SPLIT)

# Pick a checkpoint by benchmark F1 instead of validation loss, on dev.
select-checkpoint:
	python -m evaluation.select_checkpoint --run $(RUN_NAME) --split dev

# Re-validate on the split that was never inspected while tuning rules.
score-dev:
	python -m evaluation.run_eval --systems rules-only --split dev --out-dir evaluation/results_dev --force --no-score
	python -m evaluation.score --split dev --results-dir evaluation/results_dev

# ── Training ─────────────────────────────────────────────────────────────────────
# Run as a module from the repo root — train.py imports `training.config`, so
# `cd training && python train.py` cannot resolve its own package.
RUN_NAME ?= qwen1.5b-sft
ADAPTER ?= training/checkpoints/$(RUN_NAME)/final_adapter

build-data:
	python -m training.data.build_dataset --examples 6000

train:
	python -m training.train --run-name $(RUN_NAME)

merge-model:
	python -m training.merge_adapter

# ── Config audit ─────────────────────────────────────────────────────────────────
# Reports unknown .env keys and any secret left at a placeholder value.
check-config:
	cd backend && python -m app.config

# ── Benchmarks ───────────────────────────────────────────────────────────────────
benchmark:
	python scripts/benchmark_ast.py

# ── VS Code Extension ─────────────────────────────────────────────────────────────
ext-build:
	cd vscode-extension && npm run compile

ext-package:
	cd vscode-extension && vsce package

ext-publish:
	cd vscode-extension && vsce publish
