.PHONY: install dev demo test lint docker-build docker-up k8s-apply helm-lint

install:
	python3 -m venv .venv
	.venv/bin/pip install -U pip
	.venv/bin/pip install -e ".[dev]"

dev:
	.venv/bin/uvicorn anomaly_detection.main:app --reload --host 127.0.0.1 --port 8080

demo:
	DEMO_MODE=true .venv/bin/python -m anomaly_detection.demo.run

test:
	.venv/bin/pytest -q

lint:
	.venv/bin/python -m compileall src

docker-build:
	docker build -t k8s-anomaly-detection:local .

docker-up:
	docker compose up --build

k8s-apply:
	kubectl apply -f k8s/

helm-lint:
	helm lint charts/k8s-anomaly-detection
	helm template anomaly charts/k8s-anomaly-detection >/dev/null
