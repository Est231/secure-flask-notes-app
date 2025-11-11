import os
import mysql.connector


def test_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='notes_app_user',
            password=os.getenv('DB_PASSWORD'),
            database='notes_app_db',
            port=3306
        )

        if conn.is_connected():
            print("✅ Успешное подключение к MySQL!")

            cursor = conn.cursor()
            cursor.execute("SELECT DATABASE()")
            db_name = cursor.fetchone()
            print(f"📊 База данных: {db_name[0]}")

            cursor.execute("SELECT USER()")
            user = cursor.fetchone()
            print(f"👤 Пользователь: {user[0]}")

            cursor.close()
            conn.close()
            print("🔌 Подключение закрыто")

        return True

    except mysql.connector.Error as e:
        print(f"❌ Ошибка подключения: {e}")
        return False


if __name__ == "__main__":
    test_connection()