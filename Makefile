.PHONY: up db logs down migrate-up migrate-down migrate-version migrate-create

up:
	docker compose up --build -d

db:
	docker compose up -d postgres

logs:
	docker compose logs -f api

down:
	docker compose down

migrate-up:
	docker compose run --rm migrate up

migrate-down:
	docker compose run --rm migrate down 1

migrate-version:
	docker compose run --rm migrate version

migrate-create:
	@if [ -z "$(name)" ]; then echo "Ошибка: укажите имя миграции, например: make migrate-create name=init_schema"; exit 1; fi
	docker compose run --rm --no-deps --entrypoint migrate migrate create -ext sql -dir /migrations -seq $(name)