.PHONY: setup certs build up down restart logs ps seed test clean

setup:
	bash scripts/setup.sh

certs:
	bash scripts/generate-certs.sh

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

ps:
	docker compose ps

seed:
	docker compose run --rm -v $(CURDIR)/scripts:/seed --entrypoint python correlator /seed/seed_synthetic_alerts.py

test:
	docker compose run --rm -v $(CURDIR)/backend:/app --entrypoint sh backend -c \
		"pip install -q -r requirements-dev.txt && python -m pytest -q tests"
	docker compose run --rm -v $(CURDIR)/correlator:/app --entrypoint sh correlator -c \
		"pip install -q -r requirements-dev.txt && python -m pytest -q tests"

clean:
	docker compose down -v
