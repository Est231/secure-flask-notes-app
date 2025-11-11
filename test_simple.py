import subprocess

def test_function():
    # Эта уязвимость должна быть найдена
    result = subprocess.call("ls -la", shell=True)
    return result

# Хардкод пароля
password = "secret123"

if __name__ == "__main__":
    test_function()