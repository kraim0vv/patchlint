# PatchLint - Security Linter с готовыми конфигурациями для Nginx, Apache и веб-фреймворков

PatchLint - утилита динамического анализа защищенности (DAST) и Security Linter для локального аудита веб-приложений разработчиков.

Главное преимущество PatchLint: инструмент не просто находит уязвимости и ошибки конфигурации, но и предоставляет готовые проверенные рецепты устранения (Remediation) для Nginx, Apache, Express.js, Django, Flask и FastAPI.

Языковые версии:
- [Русская версия (README.ru.md)](README.ru.md)
- [English version (README.en.md)](README.en.md)

---

## Ключевые возможности

- Асинхронный сетевой стек (httpx):
  - Высокая скорость за счет параллельных проверок и пула соединений (httpx.Limits).
  - Управление таймаутами и ограничение конкурентности (--concurrency).
  - Поддержка режима --insecure (-k) для локальных самоподписанных SSL/TLS-сертификатов (https://localhost).
  - Обработка сбоев: таймауты, сброс соединения, DNS-ошибки (getaddrinfo failed).
- Защита от ложных срабатываний (False Positives):
  - Автоматическое обнаружение SPA-маршрутизации (когда React, Vue, Angular отдают HTTP 200 с index.html на любой несуществующий путь).
  - Валидация заголовка Content-Type (application/json, application/yaml) и структуры распарсенного словаря (JSON parsing).
  - Валидация сигнатур содержимого (проверка формата хешей в /.git/HEAD и синтаксиса KEY=VALUE в /.env), а не только HTTP-кода ответа.
- Информативный терминальный вывод (rich):
  - Цветовая дифференциация уровней критичности (CRITICAL, HIGH, MEDIUM, LOW, INFO).
  - Интерактивный спиннер и прогресс-бар в реальном времени.
  - Таблицы статистики и блоки рекомендаций с подсветкой синтаксиса конфигураций.
- Экспорт отчетов (JSON и HTML):
  - JSON (--format json -o report.json): машиночитаемый формат со структурой для интеграции в CI/CD (GitHub Actions, GitLab CI).
  - HTML (--format html -o report.html): автономный интерактивный дашборд (работает без интернета, без внешних CDN), с фильтрацией по критичности, поиском и кнопкой копирования готовых конфигов в один клик.
- Модульная Rule-based архитектура:
  - Полное отделение логики проверок от сетевого движка.
  - Легкое добавление собственных проверок в несколько строк кода.

---

## Структура проекта

```text
d:\webchec\
├── patchlint\
│   ├── __init__.py           # Экспорт основных сущностей пакета
│   ├── __main__.py           # Точка входа для запуска через python -m patchlint
│   ├── cli.py                # Консольный интерфейс (Click + Rich)
│   ├── engine.py             # Асинхронный DAST-движок на HTTPX
│   ├── models.py             # Датаклассы (Severity, Finding, Remediation, ScanReport)
│   ├── reporter.py           # Генераторы отчетов (Terminal, JSON, HTML)
│   ├── rules\
│   │   ├── __init__.py       # Реестр правил (RuleRegistry)
│   │   ├── base.py           # Базовые классы (BaseRule, HeaderRule, PathExposureRule, MultiPathExposureRule)
│   │   ├── headers.py        # Проверки HTTP Security Headers
│   │   └── exposure.py       # Проверки утечек файлов (/.env, /.git, config, dump, openapi) и Debug Mode
│   └── templates\
│       ├── __init__.py
│       └── report_template.html  # Интерактивный автономный HTML-отчет
├── tests\
│   ├── __init__.py
│   ├── test_cli.py           # Тесты CLI exit-кодов и порогов --fail-on
│   ├── test_rules.py         # Юнит-тесты правил, respx моки, ложные срабатывания
│   └── test_engine.py        # Тесты движка и сериализации отчетов
├── demo_target.py            # Уязвимый тестовый локальный сервер (стандартная библиотека Python)
├── requirements.txt          # Зависимости проекта
├── pyproject.toml            # Метаданные сборки и регистрация CLI-команды
├── setup.py                  # Установочный скрипт
├── README.md                 # Главный файл документации
├── README.ru.md              # Документация на русском языке
└── README.en.md              # Документация на английском языке
```

---

## Установка и запуск

### 1. Требования
- Python 3.10 или выше.

### 2. Создание виртуального окружения и установка
```bash
# Перейдите в папку проекта
cd d:\webchec

# Создайте виртуальное окружение
python -m venv venv

# Активируйте окружение:
# Для Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Для Linux / macOS:
source venv/bin/activate

# Установите зависимости:
pip install -r requirements.txt

# Установите утилиту в систему в dev-режиме:
pip install -e .
```

---

## Примеры использования

### Базовое сканирование локального сервера:
```bash
patchlint http://localhost:8000
# или без предварительной установки пакета:
python -m patchlint http://localhost:8000
```

### Экспорт интерактивного HTML-отчета:
```bash
patchlint http://localhost:8000 -f html -o audit_report.html
```

### Экспорт в JSON (для CI/CD):
```bash
patchlint http://localhost:8000 -f json -o scan_results.json
```

### Аудит HTTPS с самоподписанным сертификатом (--insecure / -k):
```bash
patchlint https://localhost:8443 -k
```

### Проверка только заголовков безопасности (без сканирования файлов):
```bash
patchlint http://localhost:8000 --headers-only
```

### Фильтрация по минимальной критичности:
```bash
patchlint http://localhost:8000 -s HIGH
```

### Просмотр всех доступных правил:
```bash
patchlint --list-rules
```

---

## Проверка на тестовом сервере (Demo Target)

В проект включен тестовый сервер demo_target.py, эмулирующий веб-сервер с типичными уязвимостями:
- Отсутствие CSP, HSTS, X-Frame-Options, X-Content-Type-Options.
- Утечка баннеров Server: Apache/2.4.41 и X-Powered-By: PHP/8.1.0.
- Доступный /.env с тестовыми паролями и ключами.
- Доступный /.git/HEAD.
- Доступный /docker-compose.yml и /dump.sql.
- Доступная спецификация /openapi.json.
- Активный Debug Mode (страница ошибки с Werkzeug Traceback).

### Запуск проверки:

В первом окне терминала:
```bash
python demo_target.py
# Сервер запустится на http://127.0.0.1:8888
```

Во втором окне терминала:
```bash
patchlint http://127.0.0.1:8888 -f html -o demo_report.html
```

---

## Базовый набор проверок v1.0

### Категория: Security Headers
| ID правила | Уровень | Описание проблемы |
| :--- | :--- | :--- |
| missing-csp-header | HIGH | Отсутствие Content-Security-Policy. Риск XSS и инъекций данных. |
| missing-hsts-header | HIGH | Отсутствие Strict-Transport-Security. Риск MitM и SSL-stripping. |
| missing-x-frame-options | MEDIUM | Отсутствие защиты от Clickjacking (встраивания во фреймы). |
| missing-x-content-type-options | LOW | Отсутствие nosniff. Риск подмены MIME-типов браузером. |
| missing-referrer-policy | LOW | Отсутствие контроля утечки приватных URL-параметров в Referer. |
| server-version-disclosure | LOW | Заголовок Server раскрывает версии ПО (например, nginx/1.18.0). |
| technology-disclosure-header | LOW | Заголовок X-Powered-By раскрывает используемый стек (PHP, Express). |

### Категория: Information Disclosure & Exposed Files
| ID правила | Уровень | Описание проблемы |
| :--- | :--- | :--- |
| exposed-env-file | CRITICAL | Публично доступен файл конфигурации /.env с секретами и паролями БД. |
| exposed-git-directory | CRITICAL | Публично доступен /.git/HEAD. Риск полной выгрузки репозитория. |
| exposed-database-dump | CRITICAL | Публично доступен дамп БД /dump.sql со структурой и записями. |
| exposed-docker-compose | HIGH | Доступен /docker-compose.yml, раскрывающий архитектуру сервисов. |
| exposed-config-json | HIGH | Доступен файл конфигурации /config.json. |
| exposed-swagger-spec | LOW | Доступна спецификация OpenAPI/Swagger (/openapi.json, /swagger.json, /api/openapi.json, /v2/api-docs). |

### Категория: Misconfiguration
| ID правила | Уровень | Описание проблемы |
| :--- | :--- | :--- |
| debug-mode-enabled | HIGH | Включен режим отладки (Django Debug, Werkzeug Traceback, Laravel Ignition). Риск RCE и утечки трассировок. |

---

## Добавление собственного правила

Добавление нового правила выполняется через наследование от BaseRule, HeaderRule, PathExposureRule или MultiPathExposureRule:

```python
from patchlint.models import Severity, Category, Remediation, RemediationExample
from patchlint.rules.base import PathExposureRule

class ExposedGraphQLRule(PathExposureRule):
    def __init__(self):
        super().__init__(
            rule_id="exposed-graphql-endpoint",
            severity=Severity.LOW,
            category=Category.INFORMATION_DISCLOSURE,
            title="Exposed GraphQL Endpoint",
            description="GraphQL endpoint is publicly accessible.",
            remediation=Remediation(
                guidance="Disable GraphQL introspection and playground in production.",
                examples=[
                    RemediationExample(
                        title="FastAPI: Disable GraphQL introspection",
                        language="python",
                        snippet="app.add_route('/graphql', GraphQLApp(schema=schema, introspection=False))"
                    )
                ]
            ),
            path="/graphql",
            signature_strings=['"__schema"', '"IntrospectionQuery"'],
        )
```

Регистрация правила в реестре:
```python
from patchlint.rules import RuleRegistry

registry = RuleRegistry()
registry.register(ExposedGraphQLRule())
```

---

## Коды возврата CLI (для CI/CD)

- 0: Проверка прошла успешно, блокирующих проблем нет.
- 1: Найдены проблемы с критичностью >= порогу флага --fail-on (дефолт: HIGH).
- 2: Сетевая ошибка (хост недоступен, ConnectionRefused, таймаут).
- 3: Ошибка аргументов командной строки.

---

## Запуск тестов

```bash
pytest -v
```
