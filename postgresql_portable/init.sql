
-- Инициализация базы данных для практической работы
CREATE DATABASE security_practice;

-- Создаем пользователя с минимальными правами
CREATE USER app_user WITH PASSWORD 'secure_pass_123';

-- Подключаемся к базе
\c security_practice

-- Отзываем права у PUBLIC
REVOKE ALL ON DATABASE security_practice FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Даем права пользователю
GRANT CONNECT ON DATABASE security_practice TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;

-- Создаем таблицу
CREATE TABLE secure_data (
    id SERIAL PRIMARY KEY,
    data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Даем только SELECT, INSERT права
GRANT SELECT, INSERT ON secure_data TO app_user;
GRANT USAGE ON SEQUENCE secure_data_id_seq TO app_user;

-- Вставляем тестовые данные
INSERT INTO secure_data (data) VALUES ('Тестовые данные 1');
INSERT INTO secure_data (data) VALUES ('Тестовые данные 2');
