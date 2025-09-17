# WindowsLogChecker

Мониторинг событий безопасности Windows (Event ID 4625) с уведомлениями в Telegram. 
Скрипт отслеживает неудачные попытки входа (в т.ч. RDP — LogonType 10) за указанный период времени и отправляет сводку в Telegram. Полезен для выявления брутфорс-атак и оперативного реагирования (например, блокировки IP на фаерволе).

## Возможности
- Отслеживание событий 4625 в `Security.evtx`
- Агрегация по IP-адресу с подсчётом количества попыток
- Фильтрация по временному окну (например, последние 60 минут)
- Уведомления в Telegram (бот + чат)
- Работа с копией журнала (без блокировки исходного файла)
- Двуязычная поддержка (RU/EN)

## Требования
- Windows 10/11/Server с доступом к журналу безопасности
- Python 3.9+
- Права чтения `C:\Windows\System32\winevt\Logs\Security.evtx`

## Установка
```powershell
# Клонирование репозитория
git clone https://github.com/VladislavFl/WindowsLogChecker.git

# Переход в директорию проекта
cd WindowsLogChecker

# Установка зависимостей
pip install -r requirements.txt
```

## Настройка
1. Создайте Telegram-бота через @BotFather и получите токен.
2. Узнайте ID чата (группы/канала), куда отправлять уведомления.
3. Скопируйте шаблон конфига и заполните его:
```powershell
copy config.ini.template config.ini
```
Откройте `config.ini` и укажите значения:
```ini
[TELEGRAM]
TOKEN = <TELEGRAM_BOT_TOKEN>
CHAT_ID = <TELEGRAM_CHAT_OR_CHANNEL_ID>

[GENERAL]
LANG = ru  ; ru или en

[PATHS]
SRC_PATH = C:\\Windows\\System32\\winevt\\Logs\\Security.evtx
DST_PATH = Security.evtx

[SCAN]
PERIOD_MINUTES = 60
SLEEP_MINUTES = 60
```

Можно задать язык и секреты через переменные окружения (имеют приоритет):
```powershell
setx APP_LANG "ru"      # или en
setx TELEGRAM_TOKEN "ВАШ_ТОКЕН"
setx TELEGRAM_CHAT_ID "ВАШ_CHAT_ID"
```

Важно: `config.ini` и временные файлы исключены из репозитория с помощью `.gitignore`.

## Запуск
```powershell
python main.py
```
Скрипт работает в бесконечном цикле: копирует журнал, парсит события 4625 за последние `PERIOD_MINUTES` минут и отправляет сводку. Пауза между циклами — `SLEEP_MINUTES`.

## Рекомендации по эксплуатации
- Для постоянного запуска используйте Планировщик заданий (Task Scheduler) или NSSM/WinSW как сервис.
- Ограничьте права аккаунта, под которым запускается скрипт, до необходимых.
- Настройте ротацию логов и мониторинг доступности бота.

## Зависимости
См. `requirements.txt`.

## Лицензия
MIT.
