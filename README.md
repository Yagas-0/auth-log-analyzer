# Анализатор логов авторизации

Небольшой учебный CLI-инструмент на Python: проверяет строки журнала, загружает события в SQLite и показывает неудачные входы и подозрительную активность. Дополнительно умеет считать неудачи по IP через Redis; если Redis или библиотека `redis` недоступны, использует JSON-файл.

## Требования

- Python 3.9 или новее
- Для SQLite-режима дополнительная установка пакетов не нужна
- Для Redis-режима: установленный Redis и зависимости из `requirements.txt`

## Установка

```bash
git clone https://github.com/Yagas-0/auth-log-analyzer.git
cd auth-log-analyzer
python -m venv .venv
```

Активируйте виртуальное окружение и установите зависимости:

```bash
# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Чтобы запускать тесты, установите dev-зависимости:

```bash
pip install -r requirements-dev.txt
```

## Формат входного файла

По умолчанию программа читает `auth.log` из текущей папки. Каждая непустая строка должна содержать четыре поля через запятую:

```text
YYYY-MM-DD HH:MM:SS,username,IP,result
```

`result` должен быть `success` или `failure`; IP и дата проверяются при загрузке. Пример файла находится в корне репозитория. Некорректные строки пропускаются с сообщением.

## Использование

Полный отчёт SQLite:

```bash
python main.py
```

Указать другой лог и порог подозрительных неудач (число неудач должно быть строго больше порога):

```bash
python main.py --log other.log --threshold 5
```

Ограничить отчёт интервалом времени (границы включаются):

```bash
python main.py --from "2026-11-03 14:00:00" --to "2026-11-03 14:05:00"
```

Подсчёт через Redis или автоматический переход на JSON, если Redis недоступен:

```bash
python main.py --backend redis
```

Выходной файл JSON называется `failed_counts.json`. База SQLite создаётся как `auth.db`.

## Redis

Запустите Redis локально, например через Docker:

```bash
docker run --rm -p 6379:6379 redis
```

В другом терминале выполните команду с `--backend redis`. При успешном подключении вывод укажет `Анализ через Redis`. Ключи проекта используют префикс `auth-log-analyzer:failed:`.

## Тесты

```bash
pytest
```

Тесты используют временную SQLite-базу и `fakeredis`; настоящий Redis для них не требуется.
