from waitress import serve
from app import app

if __name__ == "__main__":
    print("🚀 Production сервер запущен на http://127.0.0.1:5001")
    print("🛡️  Все security headers активированы")
    print("⚠️  Для HSTS нужен HTTPS в production")
    print("⏹️  Остановка: Ctrl+C")

    serve(
        app,
        host='127.0.0.1',
        port=5001,
        threads=4,
        ident=None
    )