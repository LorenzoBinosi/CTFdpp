.PHONY: build check down logs local up

build:
	docker compose -f compose.yml build

check:
	cargo fmt --all --check
	cargo check --workspace --all-targets --offline
	cargo test --workspace --all-targets --offline
	cargo clippy --workspace --all-targets --offline -- -D warnings
	python3 -m compileall -q backend/ctfzone_web
	cd backend && python3 -m unittest discover -s tests -v
	python3 -m py_compile remote-helper/ctfzone-runtime-helper
	sh -n remote-helper/install.sh
	POSTGRES_PASSWORD=compose-check-only SECRET_KEY=compose-check-only SETUP_TOKEN=compose-check-only docker compose -f compose.yml config --quiet

down:
	docker compose -f compose.yml down

logs:
	docker compose -f compose.yml logs -f

local:
	docker compose -f compose.yml -f compose.local.yml up --build

up:
	docker compose -f compose.yml up --build -d
