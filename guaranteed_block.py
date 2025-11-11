import subprocess
import pickle
import marshal

# Критические уязвимости, которые Bandit НЕ может пропустить:

# 1. B602 - subprocess with shell=True (CRITICAL)
def run_shell(cmd):
    return subprocess.call(cmd, shell=True)

# 2. B301 - pickle deserialization (CRITICAL)  
def load_pickle(data):
    return pickle.loads(data)

# 3. B302 - marshal deserialization (CRITICAL)
def load_marshal(data):
    return marshal.loads(data)

# 4. B101 - assert used (CRITICAL in production)
assert True, "This should fail"

# 5. B105 - hardcoded password (MEDIUM)
PASSWORD = "HardcodedSecret123!"

# Вызовем все опасные функции
if __name__ == "__main__":
    run_shell("echo 'Dangerous!'")
    load_pickle(pickle.dumps({"test": "data"}))
    load_marshal(marshal.dumps([1, 2, 3]))
    print("This code should be BLOCKED")