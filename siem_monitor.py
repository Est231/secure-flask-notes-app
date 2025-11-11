#!/usr/bin/env python3
"""
SIEM Lite - Система мониторинга безопасности
Обнаруживает подозрительную активность в логах Flask
"""

import os
import re
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
from pathlib import Path


class SecurityMonitor:
    def __init__(self):
        self.setup_directories()
        self.alert_count = 0
        self.incident_types = defaultdict(int)

        # Хранилище для обнаружения атак
        self.failed_logins = defaultdict(lambda: deque(maxlen=10))  # IP -> timestamps
        self.suspicious_ips = set()

        # Паттерны для обнаружения атак
        self.sql_injection_patterns = [
            r"'.*OR.*1=1",
            r"UNION.*SELECT",
            r"DROP.*TABLE",
            r"INSERT.*INTO",
            r"DELETE.*FROM",
            r"xp_cmdshell",
            r"script.*alert",
            r"<script>"
        ]

        self.sensitive_endpoints = [
            '/admin', '/api/delete', '/config', '/env',
            '/.env', '/phpmyadmin', '/mysql', '/backup'
        ]

        print("[LOCK] SIEM Security Monitor запущен...")
        print("[FOLDER] Логи отслеживаются в папке: logs/")
        print("[ALERT] Оповещения записываются в: logs/security_alerts.log")
        print("=" * 60)

    def setup_directories(self):
        """Создание необходимых директорий"""
        Path("logs").mkdir(exist_ok=True)

    def log_alert(self, alert_type, message, ip="N/A", details=""):
        """Запись оповещения о безопасности"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_entry = f"[{timestamp}] [{alert_type}] IP: {ip} - {message}"
        if details:
            alert_entry += f" | Details: {details}"

        # Запись в файл оповещений
        with open("logs/security_alerts.log", "a", encoding="utf-8") as f:
            f.write(alert_entry + "\n")

        # Цветной вывод в консоль (для систем, поддерживающих цвета)
        colors = {
            "BRUTE_FORCE": "",  # Красный текст
            "SQL_INJECTION": "",  # Желтый текст
            "UNAUTHORIZED_ACCESS": "",  # Фиолетовый текст
            "SUSPICIOUS_ACTIVITY": ""  # Голубой текст
        }

        color_prefix = {
            "BRUTE_FORCE": "[BRUTE]",
            "SQL_INJECTION": "[SQL-INJ]",
            "UNAUTHORIZED_ACCESS": "[UNAUTH]",
            "SUSPICIOUS_ACTIVITY": "[SUSP]"
        }

        prefix = color_prefix.get(alert_type, "[ALERT]")
        print(f"{prefix} {alert_entry}")

        self.alert_count += 1
        self.incident_types[alert_type] += 1

    def detect_brute_force(self, ip, timestamp):
        """Обнаружение множественных неудачных попыток входа"""
        self.failed_logins[ip].append(timestamp)

        # Проверяем количество попыток за последнюю минуту
        time_threshold = timestamp - timedelta(minutes=1)
        recent_failures = [t for t in self.failed_logins[ip] if t > time_threshold]

        if len(recent_failures) >= 5:  # 5+ неудачных попыток за минуту
            if ip not in self.suspicious_ips:
                self.suspicious_ips.add(ip)
                self.log_alert(
                    "BRUTE_FORCE",
                    f"Обнаружена атака перебора паролей",
                    ip,
                    f"{len(recent_failures)} неудачных попыток за 1 минуту"
                )

    def detect_sql_injection(self, log_line, ip):
        """Обнаружение попыток SQL инъекций"""
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, log_line, re.IGNORECASE):
                self.log_alert(
                    "SQL_INJECTION",
                    f"Обнаружена попытка SQL инъекции",
                    ip,
                    f"Паттерн: {pattern}"
                )
                return True
        return False

    def detect_unauthorized_access(self, endpoint, ip, status_code):
        """Обнаружение несанкционированного доступа"""
        # Проверка доступа к чувствительным эндпоинтам
        for sensitive_endpoint in self.sensitive_endpoints:
            if sensitive_endpoint in endpoint:
                self.log_alert(
                    "UNAUTHORIZED_ACCESS",
                    f"Попытка доступа к защищенному ресурсу",
                    ip,
                    f"Endpoint: {endpoint}, Status: {status_code}"
                )
                return True

        # Обнаружение множественных 404 ошибок (сканирование)
        if status_code in [403, 404]:
            self.log_alert(
                "SUSPICIOUS_ACTIVITY",
                f"Подозрительный код ответа",
                ip,
                f"Endpoint: {endpoint}, Status: {status_code}"
            )
            return True

        return False

    def parse_flask_log(self, line):
        """Анализ логов Flask - улучшенная версия"""
        try:
            # Упрощенный парсинг - ищем ключевые фразы
            ip_match = re.search(r'IP: \[([\d\.]+)\]', line)
            ip = ip_match.group(1) if ip_match else "N/A"

            # Обнаружение неудачных входов
            if "Failed login attempt" in line:
                self.detect_brute_force(ip, datetime.now())

            # Обнаружение SQL инъекций в параметрах запроса
            if any(pattern in line for pattern in [" OR ", "UNION", "DROP", "INSERT", "SELECT"]):
                if any(sql_pattern in line for sql_pattern in ["' OR", "UNION SELECT", "DROP TABLE"]):
                    self.detect_sql_injection(line, ip)

            # Обнаружение доступа к защищенным эндпоинтам
            for endpoint in self.sensitive_endpoints:
                if endpoint in line:
                    status_match = re.search(r'Status: (\d{3})', line)
                    status_code = int(status_match.group(1)) if status_match else 403
                    self.detect_unauthorized_access(endpoint, ip, status_code)
                    break

        except Exception as e:
            print(f"[ERROR] Ошибка парсинга лога: {e}")

    def tail_file(self, filename, callback):
        """Чтение новых строк в файле (аналог tail -f)"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                # Перемещаемся в конец файла
                f.seek(0, 2)

                while True:
                    line = f.readline()
                    if line:
                        callback(line.strip())
                    else:
                        time.sleep(0.1)  # Пауза перед проверкой новых данных
        except FileNotFoundError:
            print(f"[WARN] Файл {filename} не найден. Ожидание создания...")
            time.sleep(5)
        except Exception as e:
            print(f"[ERROR] Ошибка чтения файла {filename}: {e}")

    def generate_daily_report(self):
        """Генерация ежедневного отчета"""
        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_filename = f"logs/daily_security_report_{datetime.now().strftime('%Y%m%d')}.txt"

        report_content = f"""
ЕЖЕДНЕВНЫЙ ОТЧЕТ О БЕЗОПАСНОСТИ
Дата генерации: {report_time}
========================================

СТАТИСТИКА ИНЦИДЕНТОВ:
----------------------
Всего обнаружено инцидентов: {self.alert_count}

Детали по типам:
- Атаки перебора: {self.incident_types['BRUTE_FORCE']}
- SQL инъекции: {self.incident_types['SQL_INJECTION']}
- Несанкционированный доступ: {self.incident_types['UNAUTHORIZED_ACCESS']}
- Подозрительная активность: {self.incident_types['SUSPICIOUS_ACTIVITY']}

ПОДОЗРИТЕЛЬНЫЕ IP-АДРЕСА:
-------------------------
{chr(10).join(f"- {ip}" for ip in self.suspicious_ips) if self.suspicious_ips else "Не обнаружено"}

РЕКОМЕНДАЦИИ:
-------------
{self.generate_recommendations()}

Отчет сгенерирован автоматически системой SIEM Lite
        """

        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(report_content)

        print(f"[REPORT] Ежедневный отчет сохранен: {report_filename}")

    def generate_recommendations(self):
        """Генерация рекомендаций по безопасности"""
        recommendations = []

        if self.incident_types['BRUTE_FORCE'] > 0:
            recommendations.append("• Рассмотреть внедрение CAPTCHA для форм входа")
            recommendations.append("• Настроить блокировку IP после множественных неудачных попыток")

        if self.incident_types['SQL_INJECTION'] > 0:
            recommendations.append("• Убедиться, что все запросы к БД используют параметризацию")
            recommendations.append("• Рассмотреть использование WAF (Web Application Firewall)")

        if self.incident_types['UNAUTHORIZED_ACCESS'] > 0:
            recommendations.append("• Усилить мониторинг чувствительных эндпоинтов")
            recommendations.append("• Рассмотреть внедрение двухфакторной аутентификации")

        if not recommendations:
            recommendations.append("• Критических проблем не обнаружено. Продолжайте мониторинг")

        return '\n'.join(recommendations)

    def start_monitoring(self):
        """Запуск мониторинга"""
        print("[START] Запуск мониторинга логов...")

        # Запуск мониторинга в отдельных потоках
        flask_thread = threading.Thread(
            target=self.tail_file,
            args=("logs/flask_app.log", self.parse_flask_log),
            daemon=True
        )

        flask_thread.start()

        print("[OK] Мониторинг запущен. Ожидание событий...")
        print("[INFO] Для тестирования запустите test_security_events.py в отдельном терминале")

        # Главный цикл
        last_report_time = datetime.now()
        try:
            while True:
                time.sleep(10)  # Проверка каждые 10 секунд

                # Автоматическая генерация отчета каждые 24 часа
                current_time = datetime.now()
                if (current_time - last_report_time).total_seconds() >= 86400:  # 24 часа
                    self.generate_daily_report()
                    last_report_time = current_time

                # Вывод статуса каждые 30 секунд
                if int(time.time()) % 30 == 0:
                    print(
                        f"[STATUS] Обнаружено {self.alert_count} инцидентов, {len(self.suspicious_ips)} подозрительных IP")

        except KeyboardInterrupt:
            print("\n[STOP] Остановка мониторинга...")
            self.generate_daily_report()  # Финальный отчет при остановке


def main():
    """Основная функция"""
    monitor = SecurityMonitor()
    monitor.start_monitoring()


if __name__ == "__main__":
    main()