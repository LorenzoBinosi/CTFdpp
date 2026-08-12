.PHONY: build check compose-check down logs local up

COMPOSE_CHECK_ENV = \
	CADDY_SITE_ADDRESS=https://ctf.example.test \
	CADDY_STORAGE_ADDRESS=https://files.ctf.example.test \
	POSTGRES_PASSWORD=compose-check-only \
	SECRET_KEY=compose-check-browser-key \
	BACKEND_SERVICE_TOKEN=compose-check-backend-token \
	API_SIGNING_KEY=compose-check-api-signing-key \
	SETUP_TOKEN=compose-check-setup-token \
	OBJECT_STORAGE_ACCESS_KEY=compose-check-storage-access \
	OBJECT_STORAGE_SECRET_KEY=compose-check-storage-secret

build:
	docker compose -f compose.yml build

check:
	cargo fmt --all --check
	cargo check --workspace --all-targets --offline
	cargo test --workspace --all-targets --offline
	cargo clippy --workspace --all-targets --offline -- -D warnings
	python3 -m compileall -q backend/ctfzone_web
	cd backend && python3 -m unittest discover -s tests -v
	python3 -m unittest remote-helper/test_runtime_helper.py -v
	python3 -m py_compile remote-helper/ctfzone-runtime-helper
	sh -n remote-helper/install.sh
	$(MAKE) compose-check

compose-check:
	$(COMPOSE_CHECK_ENV) docker compose -f compose.yml config --quiet
	$(COMPOSE_CHECK_ENV) docker compose -f compose.yml -f compose.local.yml config --quiet

down:
	docker compose -f compose.yml down

logs:
	docker compose -f compose.yml logs -f

local:
	docker compose -f compose.yml -f compose.local.yml up --build

up:
	docker compose -f compose.yml up --build -d
