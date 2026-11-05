
# Information Exchange Service

REST API для обмена информацией об угрозах по MD5-хешу.

## Стек

- Go
- PostgreSQL
- pgx
- Docker Compose
- golang-migrate
- Testcontainers
- OpenAPI 3.0

## Запуск

Создать файл конфигурации:

```bash
cp .env.example .env
```

Запустить PostgreSQL:

```bash
make db
```

Применить миграции:

```bash
make migrate-up
```

Запустить приложение:

```bash
make up
```

API доступно по адресу `http://localhost:8080`
(при стандартной конфигурации).

## Конфигурация

Настройки приложения задаются через `.env`.

Основные параметры:

| Переменная | Описание |
|---|---|
| POSTGRES_HOST | Хост PostgreSQL |
| POSTGRES_PORT | Порт PostgreSQL |
| POSTGRES_USER | Пользователь БД |
| POSTGRES_PASSWORD | Пароль БД |
| POSTGRES_DB | Название БД |
| HTTP_HOST | Адрес HTTP-сервера |
| HTTP_PORT | Порт HTTP-сервера |
| LOG_LEVEL | Уровень логирования |

Полный список переменных находится в `.env.example`.

## API

### POST /info

Создание новой угрозы.

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "name": "Trojan.Win32.Generic",
  "description": "Malicious executable",
  "severity": "high"
}
```

Ответ: `201 Created`.

### GET /info/{md5}

Получение информации об угрозе по MD5.

Ответ: `200 OK`.

### PUT /info/{md5}

Обновление существующей угрозы.

```json
{
  "name": "Trojan.Win32.Generic",
  "description": "Updated description",
  "severity": "critical"
}
```

Ответ: `200 OK`.

Поддерживаемые уровни критичности:
`low`, `medium`, `high`, `critical`.

### Ошибки

| Код | Описание |
|---|---|
| 400 | Некорректные данные |
| 404 | Угроза не найдена |
| 409 | Угроза уже существует |
| 500 | Внутренняя ошибка сервера |

Ошибки возвращаются в формате:

```json
{
  "message": "invalid threat severity",
  "details": "Allowed values: low, medium, high, critical"
}
```

## Тестирование

Запуск всех тестов:

```bash
go test ./...
```

Проверка на гонки данных:

```bash
go test -race ./...
```

Проверка покрытия:

```bash
go test -cover ./...
```

Для интеграционных тестов требуется Docker.

## Миграции

```bash
make migrate-up
make migrate-down
make migrate-version
```

## Документация API

OpenAPI-спецификация находится в файле `openapi.yaml`.
