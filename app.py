import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
import logging

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key-for-dev')

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='secure_session',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

csrf = CSRFProtect(app)

# Конфигурация подключения к PostgreSQL
DB_CONFIG = {
    'host': 'localhost',
    'user': 'app_user',
    'password': os.getenv('DB_PASSWORD', 'secure_password_123'),
    'database': 'notes_app_db',
    'port': 5432
}


def get_db_connection():
    """Создание защищенного подключения к PostgreSQL"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except psycopg2.Error as e:
        logger.error(f"Ошибка подключения к PostgreSQL: {e}")
        return None


def init_database():
    """Инициализация базы данных PostgreSQL"""
    try:
        conn = get_db_connection()
        if conn is None:
            logger.error("❌ Не удалось подключиться к БД")
            return False

        cursor = conn.cursor()

        # Создаем таблицу пользователей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Создаем таблицу заметок
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        conn.commit()

        # Создаем тестового пользователя
        cursor.execute("SELECT * FROM users WHERE username = 'testuser'")
        if not cursor.fetchone():
            test_password = os.getenv('TEST_USER_PASSWORD', 'testpassword123')
            password_hash = generate_password_hash(test_password)
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id",
                ('testuser', password_hash)
            )
            user_id = cursor.fetchone()[0]

            # Создаем тестовые заметки
            notes_data = [
                ('Первая заметка', 'Это моя первая тестовая заметка', user_id),
                ('Список покупок', 'Молоко, хлеб, яйца', user_id),
                ('Идеи для проекта', 'Разработать веб-приложение', user_id)
            ]

            for note in notes_data:
                cursor.execute(
                    "INSERT INTO notes (title, content, user_id) VALUES (%s, %s, %s)",
                    note
                )

            conn.commit()
            print("✅ Тестовый пользователь создан: testuser / testpassword123")

        cursor.close()
        conn.close()
        print("✅ База данных PostgreSQL инициализирована")
        return True

    except psycopg2.Error as e:
        print(f"❌ Ошибка инициализации БД: {e}")
        return False


# Остальные функции для PostgreSQL
def user_exists(username):
    """Проверка существования пользователя"""
    conn = get_db_connection()
    if conn is None:
        return False

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        return user is not None
    except Exception as e:
        print(f"Ошибка проверки пользователя: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def register_user(username, password):
    """Регистрация пользователя"""
    conn = get_db_connection()
    if conn is None:
        return False

    cursor = conn.cursor()
    password_hash = generate_password_hash(password)

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            (username, password_hash)
        )
        conn.commit()
        return True
    except psycopg2.IntegrityError:
        flash('Пользователь с таким именем уже существует', 'error')
        return False
    except Exception as e:
        print(f"Ошибка регистрации: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def login_user(username, password):
    """Вход пользователя"""
    conn = get_db_connection()
    if conn is None:
        return None

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            return user
        return None
    except Exception as e:
        print(f"Ошибка входа: {e}")
        return None
    finally:
        cursor.close()
        conn.close()


def get_all_notes():
    """Получение всех заметок"""
    conn = get_db_connection()
    if conn is None:
        return []

    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT notes.*, users.username 
            FROM notes 
            JOIN users ON notes.user_id = users.id 
            ORDER BY notes.created_at DESC
        """)
        notes = cursor.fetchall()
        return notes
    except Exception as e:
        print(f"Ошибка получения заметок: {e}")
        return []
    finally:
        cursor.close()
        conn.close()


def get_user_notes(user_id):
    """Получение заметок пользователя"""
    conn = get_db_connection()
    if conn is None:
        return []

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM notes WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
        notes = cursor.fetchall()
        return notes
    except Exception as e:
        print(f"Ошибка получения заметок пользователя: {e}")
        return []
    finally:
        cursor.close()
        conn.close()


def add_note_to_db(title, content, user_id):
    """Добавление заметки"""
    conn = get_db_connection()
    if conn is None:
        return None

    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO notes (title, content, user_id) VALUES (%s, %s, %s) RETURNING id",
            (title, content, user_id)
        )
        note_id = cursor.fetchone()[0]
        conn.commit()
        return note_id
    except Exception as e:
        print(f"Ошибка добавления заметки: {e}")
        return None
    finally:
        cursor.close()
        conn.close()


def update_note_in_db(note_id, title, content, user_id):
    """Обновление заметки"""
    conn = get_db_connection()
    if conn is None:
        return False

    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE notes SET title = %s, content = %s WHERE id = %s AND user_id = %s",
            (title, content, note_id, user_id)
        )
        conn.commit()
        success = cursor.rowcount > 0
        return success
    except Exception as e:
        print(f"Ошибка обновления заметки: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def delete_note_from_db(note_id, user_id):
    """Удаление заметки"""
    conn = get_db_connection()
    if conn is None:
        return False

    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM notes WHERE id = %s AND user_id = %s",
            (note_id, user_id)
        )
        conn.commit()
        success = cursor.rowcount > 0
        return success
    except Exception as e:
        print(f"Ошибка удаления заметки: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def get_note_by_id(note_id, user_id):
    """Получение заметки по ID"""
    conn = get_db_connection()
    if conn is None:
        return None

    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT * FROM notes WHERE id = %s AND user_id = %s",
            (note_id, user_id)
        )
        note = cursor.fetchone()
        return note
    except Exception as e:
        print(f"Ошибка получения заметки: {e}")
        return None
    finally:
        cursor.close()
        conn.close()


# Инициализируем базу данных
print("🔄 Инициализация базы данных PostgreSQL...")
if init_database():
    print("✅ База данных готова к работе")
else:
    print("❌ Ошибка инициализации базы данных")


# Маршруты Flask (остаются без изменений)
@app.before_request
def before_request():
    if 'user_id' not in session:
        session['user_id'] = None
    if 'username' not in session:
        session['username'] = None
    if 'note_ids' not in session:
        session['note_ids'] = []


@app.route('/')
def index():
    if not session.get('user_id'):
        return redirect(url_for('login_route'))

    notes = get_all_notes()
    user_notes = get_user_notes(session['user_id'])
    user_note_ids = [note[0] for note in user_notes]
    session['note_ids'] = user_note_ids

    notes_formatted = []
    for note in notes:
        notes_formatted.append({
            'id': note[0],
            'title': note[1],
            'content': note[2],
            'user_id': note[3],
            'created_at': note[4],
            'username': note[5]
        })

    return render_template('index.html',
                           notes=notes_formatted,
                           user_note_ids=user_note_ids,
                           username=session.get('username'))


@app.route('/login', methods=['GET', 'POST'])
def login_route():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username or not password:
            flash('Заполните все поля', 'error')
            return render_template('login.html')

        user_data = login_user(username, password)

        if user_data:
            session['user_id'] = user_data[0]
            session['username'] = user_data[1]
            flash('Успешный вход в систему!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверные учетные данные', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password:
            flash('Заполните все поля', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Пароли не совпадают', 'error')
            return render_template('register.html')

        if len(username) < 3:
            flash('Имя пользователя должно быть не менее 3 символов', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('Пароль должен быть не менее 6 символов', 'error')
            return render_template('register.html')

        if user_exists(username):
            flash('Пользователь с таким именем уже существует', 'error')
            return render_template('register.html')

        success = register_user(username, password)

        if success:
            flash('Регистрация успешна! Теперь войдите в систему.', 'success')
            return redirect(url_for('login_route'))
        else:
            flash('Ошибка регистрации', 'error')

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('login_route'))


@app.route('/add', methods=['POST'])
def add_note():
    if not session.get('user_id'):
        return redirect(url_for('login_route'))

    title = request.form['title'].strip()
    content = request.form['content'].strip()

    if not title or not content:
        flash('Заполните все поля', 'error')
        return redirect(url_for('index'))

    note_id = add_note_to_db(title, content, session['user_id'])

    user_notes = get_user_notes(session['user_id'])
    session['note_ids'] = [note[0] for note in user_notes]
    session.modified = True

    flash('Заметка добавлена!', 'success')
    return redirect(url_for('index'))


@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    if not session.get('user_id'):
        return redirect(url_for('login_route'))

    note = get_note_by_id(note_id, session['user_id'])
    if not note:
        return "Доступ запрещен!", 403

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        success = update_note_in_db(note_id, title, content, session['user_id'])
        if success:
            flash('Заметка обновлена!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Ошибка обновления заметки', 'error')

    note_formatted = {
        'id': note[0],
        'title': note[1],
        'content': note[2],
        'user_id': note[3],
        'created_at': note[4]
    }

    return render_template('edit.html', note=note_formatted)


@app.route('/delete/<int:note_id>')
def delete_note(note_id):
    if not session.get('user_id'):
        return redirect(url_for('login_route'))

    success = delete_note_from_db(note_id, session['user_id'])
    if not success:
        return "Доступ запрещен!", 403

    if note_id in session.get('note_ids', []):
        session['note_ids'].remove(note_id)
        session.modified = True

    flash('Заметка удалена!', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  ЗАПУСК ЗАЩИЩЕННОГО ПРИЛОЖЕНИЯ С POSTGRESQL")
    print("=" * 60)
    print("📊 Тестовый пользователь: testuser / testpassword123")
    print("🔒 Используются параметризованные запросы")
    print("🗄️  База данных: PostgreSQL")
    print("🚫 SQL-инъекции заблокированы")
    print("=" * 60)
    app.run(debug=False, host='127.0.0.1', port=5001)