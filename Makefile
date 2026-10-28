.DEFAULT_GOAL := help

.PHONY: help build seed up up-egress down logs ps restart triage test lint eval eval-compare redteam scorecard clean

help:  ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build:  ## Build the Docker image (multi-stage; uses uv cache mount).
	docker compose build

seed:  ## One-shot: pull CVEs from NVD and populate ChromaDB on the shared volume.
	docker compose --profile seed run --rm seed-job

up:  ## Start MCP server + agent API in the background.
	docker compose up -d

up-egress:  ## Start the stack with the opt-in egress allowlist proxy.
	docker compose -f docker-compose.yml -f docker-compose.egress.yml up -d

down:  ## Stop both services. The data volume is preserved.
	docker compose down

logs:  ## Tail logs from both services.
	docker compose logs -f

ps:  ## Show running containers.
	docker compose ps

restart:  ## Restart both services.
	docker compose restart

triage:  ## Send a query to the running agent. Usage: make triage Q="your question"
	@if [ -z "$(Q)" ]; then echo "Usage: make triage Q=\"your question\""; exit 1; fi
	@curl -N -X POST http://localhost:8000/v1/triage \
		-H "Content-Type: application/json" \
		-d '{"query": "$(Q)"}'

test:  ## Run the pytest suite locally (outside Docker).
	uv run pytest -q

lint:  ## Run backend (ruff + mypy --strict) and frontend (ESLint) lints.
	uv run ruff check src tests scripts
	uv run mypy src scripts
	cd frontend && npm run lint

ui:  ## Open the frontend UI in the default browser (assumes `make up` is running).
	@open http://localhost:3000 2>/dev/null || xdg-open http://localhost:3000 2>/dev/null || echo "Frontend at http://localhost:3000"

obs-up:  ## Start the stack WITH the Jaeger sidecar and OTLP enabled. UI on :16686.
	@OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318 docker compose --profile observability up -d
	@echo "Jaeger UI: http://localhost:16686"

obs-down:  ## Stop the observability stack (keeps the data volume).
	docker compose --profile observability down

eval:  ## Run the end-to-end golden-set eval against a live stack (needs `make up`). Bills the LLM.
	@uv run sec-recon-eval $(EVAL_ARGS)

eval-compare:  ## Run the eval suite across haiku/sonnet/opus and print a side-by-side table. Bills the LLM.
	@uv run sec-recon-eval --models haiku,sonnet,opus $(EVAL_ARGS)

redteam:  ## Run the prompt-injection battery against a live stack. Bills the LLM.
	@uv run sec-recon-redteam $(REDTEAM_ARGS)

scorecard:  ## Regenerate SCORECARD.md from deterministic coverage + any result JSONs in data/scorecard/.
	@uv run sec-recon-scorecard $(SCORECARD_ARGS)

record-cassettes:  ## Re-record replay cassettes from the golden set (needs a live MCP server). Bills the LLM.
	@uv run python scripts/record_cassettes.py $(RECORD_ARGS)

clean:  ## Stop services and DELETE the ChromaDB volume. Destructive.
	docker compose down --volumes
