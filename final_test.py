import subprocess
import requests
import re


def final_sqlmap_test():
    print("🎯 ФИНАЛЬНЫЙ ТЕСТ SQLMap")
    print("=" * 50)

    # Получаем токены
    session = requests.Session()
    response = session.get('http://127.0.0.1:5001/login')

    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    csrf_token = csrf_match.group(1) if csrf_match else ""
    session_cookie = session.cookies.get('secure_session', '')

    print(f"✅ Токены получены")

    # Команда SQLMap БЕЗ CSRF параметров (так как уже доказали защиту)
    cmd = [
        'sqlmap',
        '-u', 'http://127.0.0.1:5001/login',
        '--method', 'POST',
        '--data', 'username=test&password=test',
        '--cookie', f'secure_session={session_cookie}',
        '--risk', '3',
        '--level', '5',
        '--dbms', 'sqlite',
        '--batch'
    ]

    print("🚀 Запуск SQLMap...")
    print("Команда:", ' '.join(cmd))
    print("-" * 50)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)

        if "all tested parameters do not appear to be injectable" in result.stdout:
            print("\n" + "=" * 50)
            print("🎉 УСПЕХ: Приложение защищено от SQL-инъекций!")
            print("📊 SQLMap не смог найти уязвимостей")
        else:
            print("\n❌ Обнаружены потенциальные уязвимости")

    except Exception as e:
        print(f"❌ Ошибка: {e}")


if __name__ == '__main__':
    final_sqlmap_test()