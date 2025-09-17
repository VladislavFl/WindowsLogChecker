import configparser
import time
from datetime import datetime, timedelta, timezone
import Evtx.Evtx
import xml.etree.ElementTree as ET
import shutil
import os
import requests
import re


def main():
    config = configparser.ConfigParser()
    config.read('config.ini')
    TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN', config.get('TELEGRAM', 'TOKEN', fallback=''))
    TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', config.get('TELEGRAM', 'CHAT_ID', fallback=''))
    TELEGRAM_API_URL = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
    src_path = config.get('PATHS', 'SRC_PATH', fallback=r'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
    dst_path = config.get('PATHS', 'DST_PATH', fallback='Security.evtx')
    PERIOD_MINUTES = int(config.get('SCAN', 'PERIOD_MINUTES', fallback='60'))
    SLEEP_MINUTES = int(config.get('SCAN', 'SLEEP_MINUTES', fallback='60'))
    lang = os.getenv('APP_LANG', config.get('GENERAL', 'LANG', fallback='ru')).lower()
    if lang not in ('ru', 'en'):
        lang = 'ru'

    LOG_STR = {
        'ru': {
            'copy': "Копирование файла {src} в {dst}...",
            'copied': "Файл скопирован. Начинаю обработку...",
            'tg_ok': "Часть сообщения успешно отправлена в Telegram.",
            'tg_err': "Ошибка отправки в Telegram: {status} {text}",
            'tg_skip': "TELEGRAM_TOKEN/TELEGRAM_CHAT_ID не заданы. Пропускаю отправку уведомления.",
            'no_multi': "Нет пользователей с более чем одной неудачной попыткой входа за последние {mins} минут.",
            'none_found': "Ошибок входа (4625) за последние {mins} минут не найдено.",
            'eventid_miss': "EventID не найдено в {count} событиях, они были пропущены.",
            'proc_err': "Ошибка при обработке файла: {err}",
            'tmp_deleted': "Временный файл {dst} удалён.",
            'tmp_not_found': "Временный файл {dst} не найден для удаления.",
            'waiting': "Ожидание {mins} минут до следующей проверки...",
            'header': "Обнаружены ошибки входа 4625 за последние {mins} минут:\n\n",
            'ip': "IP",
            'attempts': "Попыток",
            'last_try': "Последняя попытка",
            'separator': "--------------\n",
            'logon_type': "Тип входа",
        },
        'en': {
            'copy': "Copying file {src} to {dst}...",
            'copied': "File copied. Starting processing...",
            'tg_ok': "Message part successfully sent to Telegram.",
            'tg_err': "Telegram send error: {status} {text}",
            'tg_skip': "TELEGRAM_TOKEN/TELEGRAM_CHAT_ID are not set. Skipping notification.",
            'no_multi': "No IPs with more than one failed login in the last {mins} minutes.",
            'none_found': "No failed logon (4625) events found in the last {mins} minutes.",
            'eventid_miss': "EventID not found in {count} events; they were skipped.",
            'proc_err': "Error processing file: {err}",
            'tmp_deleted': "Temporary file {dst} removed.",
            'tmp_not_found': "Temporary file {dst} not found for deletion.",
            'waiting': "Waiting {mins} minutes before next check...",
            'header': "Detected 4625 failed logon events in the last {mins} minutes:\n\n",
            'ip': "IP",
            'attempts': "Attempts",
            'last_try': "Last attempt",
            'separator': "--------------\n",
            'logon_type': "Logon type",
        }
    }[lang]

    logon_type_dict_ru = {
        '2': 'Interactive — Прямой вход на консоли (перед монитором/клавиатурой)',
        '3': 'Network — Сетевой доступ (например, доступ к папке по SMB, подключение к шейру)',
        '4': 'Batch — Задания планировщика задач (Scheduled Tasks)',
        '5': 'Service — Вход службы (Windows Service под учётной записью)',
        '7': 'Unlock — Разблокировка рабочей станции (после Win+L)',
        '8': 'NetworkCleartext — Сетевой вход с передачей пароля в открытом виде (редко используется)',
        '9': 'NewCredentials — "RunAs /netonly" (создание нового входа с другими учетными данными)',
        '10': 'RemoteInteractive — Удалённый рабочий стол (RDP)',
        '11': 'CachedInteractive — Вход с кэшированными данными (например, ноутбук без доступа к домену)'
    }
    logon_type_dict_en = {
        '2': 'Interactive — Local console logon',
        '3': 'Network — Network access (e.g., SMB share)',
        '4': 'Batch — Scheduled Tasks',
        '5': 'Service — Windows Service logon',
        '7': 'Unlock — Workstation unlock',
        '8': 'NetworkCleartext — Network logon with cleartext password',
        '9': 'NewCredentials — RunAs /netonly',
        '10': 'RemoteInteractive — Remote Desktop (RDP)',
        '11': 'CachedInteractive — Logon with cached credentials'
    }
    while True:
        print(LOG_STR['copy'].format(src=src_path, dst=dst_path))
        shutil.copy2(src_path, dst_path)
        print(LOG_STR['copied'])
        try:
            with Evtx.Evtx.Evtx(dst_path) as log:
                now = datetime.now(timezone.utc)
                period_start = now - timedelta(minutes=PERIOD_MINUTES)
                errors = {}
                not_found_count = 0
                logon_type_dict = logon_type_dict_ru if lang == 'ru' else logon_type_dict_en
                for record in log.records():
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    m = re.match(r'\{.*\}', root.tag)
                    ns = m.group(0) if m else ''
                    event_id_elem = root.find(f'.//{ns}EventID')
                    if event_id_elem is None:
                        not_found_count += 1
                        continue
                    event_id = event_id_elem.text
                    if event_id == "4625":
                        time_elem = root.find(f'.//{ns}TimeCreated')
                        user_elem = root.find(f'.//{ns}Data[@Name="TargetUserName"]')
                        ip_elem = root.find(f'.//{ns}Data[@Name="IpAddress"]')
                        logon_type_elem = root.find(f'.//{ns}Data[@Name="LogonType"]')
                        timestamp = time_elem.attrib['SystemTime'] if time_elem is not None and 'SystemTime' in time_elem.attrib else 'N/A'

                        try:
                            event_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
                        except Exception:
                            event_time = None
                        if event_time and not (period_start <= event_time <= now):
                            continue
                        user = user_elem.text if user_elem is not None else 'N/A'
                        ip = ip_elem.text if ip_elem is not None else 'N/A'
                        logon_type = logon_type_elem.text if logon_type_elem is not None else 'N/A'
                        unknown_text = 'Неизвестно' if lang == 'ru' else 'Unknown'
                        logon_type_text = logon_type_dict.get(logon_type, f'{unknown_text} ({logon_type})')
                        key = ip
                        if key not in errors:
                            errors[key] = {'count': 0, 'last_time': timestamp, 'logon_type': logon_type_text}
                        errors[key]['count'] += 1
                        errors[key]['last_time'] = timestamp
                        errors[key]['logon_type'] = logon_type_text
                if errors:
                    filtered_errors = {k: v for k, v in errors.items() if v['count'] > 1}
                    if filtered_errors:
                        user_blocks = []
                        for idx, (ip, info) in enumerate(filtered_errors.items()):
                            try:
                                utc_dt = datetime.strptime(info['last_time'], '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
                                local_dt = utc_dt.astimezone()  # convert to local device timezone
                                date_fmt = '%Y-%m-%d %H:%M' if lang == 'en' else '%d.%m.%Y %H:%M'
                                last_time_str = local_dt.strftime(date_fmt)
                            except Exception:
                                last_time_str = info['last_time']
                            block = (
                                f"{LOG_STR['ip']}: {ip}\n"
                                f"{LOG_STR['attempts']}: {info['count']}\n"
                                f"{LOG_STR['last_try']}: {last_time_str}\n"
                                f"{LOG_STR['logon_type']}: {info['logon_type']}\n"
                            )
                            if len(filtered_errors) > 1 and idx < len(filtered_errors) - 1:
                                block += LOG_STR['separator']
                            user_blocks.append(block)

                        header = LOG_STR['header'].format(mins=PERIOD_MINUTES)
                        messages = []
                        current_message = header
                        for block in user_blocks:
                            if len(current_message) + len(block) > 4096:
                                messages.append(current_message)
                                current_message = header + block
                            else:
                                current_message += block
                        if current_message != header:
                            messages.append(current_message)

                        for part in messages:
                            print(part)
                            if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
                                print(LOG_STR['tg_skip'])
                                continue
                            try:
                                response = requests.post(
                                    TELEGRAM_API_URL,
                                    data={'chat_id': TELEGRAM_CHAT_ID, 'text': part},
                                    timeout=10
                                )
                                if response.status_code == 200:
                                    print(LOG_STR['tg_ok'])
                                else:
                                    print(LOG_STR['tg_err'].format(status=response.status_code, text=response.text))
                            except requests.RequestException as e:
                                print(f"{e}")
                    else:
                        print(LOG_STR['no_multi'].format(mins=PERIOD_MINUTES))
                else:
                    print(LOG_STR['none_found'].format(mins=PERIOD_MINUTES))
                if not_found_count > 0:
                    print(LOG_STR['eventid_miss'].format(count=not_found_count))
        except Exception as e:
            print(LOG_STR['proc_err'].format(err=e))
        finally:
            if os.path.exists(dst_path):
                os.remove(dst_path)
                print(LOG_STR['tmp_deleted'].format(dst=dst_path))
            else:
                print(LOG_STR['tmp_not_found'].format(dst=dst_path))
        print(LOG_STR['waiting'].format(mins=SLEEP_MINUTES))
        time.sleep(SLEEP_MINUTES * 60)


if __name__ == '__main__':
    main()
