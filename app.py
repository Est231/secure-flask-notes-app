import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Без значения по умолчанию

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # Для локальной разработки
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='secure_session',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

csrf = CSRFProtect(app)

# Конфигурация подключения к MySQL
DB_CONFIG = {
    'host': 'localhost',
    'user': 'notes_app_user',
    'password': os.getenv('DB_PASSWORD'),  # Без значения по умолчанию
    'database': 'notes_app_db',
    'port': 3306
}

def get_db_connection():
    """Создание защищенного подключения к MySQL"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as e:
        print(f"Ошибка подключения к БД: {e}")
        return None

def init_database():
    """Инициализация базы данных MySQL"""
    try:
        conn = get_db_connection()
        if conn is None:
            print("❌ Не удалось подключиться к БД")
            return False

        cursor = conn.cursor()

        # Создаем таблицу пользователей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB
        ''')

        # Создаем таблицу заметок
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS note (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                user_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
            ) ENGINE=InnoDB
        ''')

        conn.commit()

        # Создаем тестового пользователя
        cursor.execute("SELECT * FROM user WHERE username = 'testuser'")
        if not cursor.fetchone():
            test_password = os.getenv('TEST_USER_PASSWORD')
            password_hash = generate_password_hash(test_password)
            cursor.execute(
                "INSERT INTO user (username, password_hash) VALUES (%s, %s)",
                ('testuser', password_hash)
            )
            user_id = cursor.lastrowid

            # Создаем тестовые заметки
            notes_data = [
                ('Первая заметка', 'Это моя первая тестовая заметка', user_id),
                ('Список покупок', 'Молоко, хлеб, яйца', user_id),
                ('Идеи для проекта', 'Разработать веб-приложение', user_id)
            ]

            cursor.executemany(
                "INSERT INTO note (title, content, user_id) VALUES (%s, %s, %s)",
                notes_data
            )

            conn.commit()
            print("✅ Тестовый пользователь создан: testuser / [HIDDEN]")

        cursor.close()
        conn.close()
        print("✅ База данных MySQL инициализирована")
        return True

    except mysql.connector.Error as e:
        print(f"❌ Ошибка инициализации БД: {e}")
        return False

# Инициализируем базу данных при старте приложения
print("🔄 Инициализация базы данных...")
if init_database():
    print("✅ База данных готова к работе")
else:
    print("❌ Ошибка инициализации базы данных")

# Остальные функции остаются без изменений...
def user_exists(username):
    """Защищенная проверка существования пользователя"""
    conn = get_db_connection()
    if conn is None:
        return False

    cursor = conn.cursor()
    query = "SELECT * FROM user WHERE username = %s"

    try:
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user is not None
    except Exception as e:
        print(f"Ошибка проверки пользователя: {e}")
        cursor.close()
        conn.close()
        return False

def register_user(username, password):
    """Защищенная регистрация пользователя"""
    conn = get_db_connection()
    if conn is None:
        return False

    cursor = conn.cursor()
    password_hash = generate_password_hash(password)
    query = "INSERT INTO user (username, password_hash) VALUES (%s, %s)"

    try:
        cursor.execute(query, (username, password_hash))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except mysql.connector.IntegrityError:
        flash('Пользователь с таким именем уже существует', 'error')
        return False
    except Exception as e:
        print(f"Ошибка регистрации: {e}")
        cursor.close()
        conn.close()
        return False

def login_user(username, password):
    """Защищенный вход пользователя"""
    conn = get_db_connection()
    if conn is None:
        return None

    cursor = conn.cursor()
    query = "SELECT * FROM user WHERE username = %s"

    try:
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user[2], password):
            return user
        return None
    except Exception as e:
        print(f"Ошибка входа: {e}")
        cursor.close()
        conn.close()
        return None

def get_all_notes():
    """Получение всех заметок"""
    conn = get_db_connection()
    if conn is None:
        return []

    cursor = conn.cursor()
    cursor.execute("""
        SELECT note.*, user.username 
        FROM note 
        JOIN user ON note.user_id = user.id 
        ORDER BY note.created_at DESC
    """)
    notes = cursor.fetchall()
    cursor.close()
    conn.close()
    return notes


def get_user_notes(user_id):
    """Получение заметок пользователя"""
    conn = get_db_connection()
    if conn is None:
        return []

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM note WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
    notes = cursor.fetchall()
    cursor.close()
    conn.close()
    return notes


def add_note_to_db(title, content, user_id):
    """Добавление заметки"""
    conn = get_db_connection()
    if conn is None:
        return None

    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO note (title, content, user_id) VALUES (%s, %s, %s)",
        (title, content, user_id)
    )
    conn.commit()
    note_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return note_id


def update_note_in_db(note_id, title, content, user_id):
    """Обновление заметки"""
    conn = get_db_connection()
    if conn is None:
        return False

    cursor = conn.cursor()
    cursor.execute(
        "UPDATE note SET title = %s, content = %s WHERE id = %s AND user_id = %s",
        (title, content, note_id, user_id)
    )
    conn.commit()
    success = cursor.rowcount > 0
    cursor.close()
    conn.close()
    return success


def delete_note_from_db(note_id, user_id):
    """Удаление заметки"""
    conn = get_db_connection()
    if conn is None:
        return False

    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM note WHERE id = %s AND user_id = %s",
        (note_id, user_id)
    )
    conn.commit()
    success = cursor.rowcount > 0
    cursor.close()
    conn.close()
    return success


def get_note_by_id(note_id, user_id):
    """Получение заметки по ID"""
    conn = get_db_connection()
    if conn is None:
        return None

    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM note WHERE id = %s AND user_id = %s",
        (note_id, user_id)
    )
    note = cursor.fetchone()
    cursor.close()
    conn.close()
    return note


# Остальные маршруты остаются без изменений
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
    # Инициализируем базу данных при запуске
    init_database()

    print("=" * 60)
    print("🛡️  ЗАПУСК ЗАЩИЩЕННОГО ПРИЛОЖЕНИЯ С MYSQL")
    print("=" * 60)
    print("📊 Тестовый пользователь: testuser / [HIDDEN]")
    print("🔒 Используются параметризованные запросы")
    print("🗄️  База данных: MySQL")
    print("🚫 SQL-инъекции заблокированы")
    print("=" * 60)
    app.run(debug=False, host='127.0.0.1', port=5001)