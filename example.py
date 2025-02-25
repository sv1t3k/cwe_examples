import hashlib
import os
import secrets
import getpass

# ОЧЕНЬ ПЛОХО: Жестко закодированные учетные данные
HARDCODED_USERNAME = "admin"
HARDCODED_PASSWORD = "password123"  # CWE-260 + CWE-256

USERS_FILE = "users.txt"

def create_user(username, password):
    """Создает нового пользователя и сохраняет его данные в файл."""
    salt = secrets.token_hex(16)
    hashed_password = hash_password(password, salt)
    with open(USERS_FILE, "a") as f:
        f.write(f"{username}:{hashed_password}:{salt}\n")
    print(f"Пользователь {username} успешно создан.")

def hash_password(password, salt):
    """Хеширует пароль с использованием соли (MD5 - небезопасно!)."""  # CWE-261 (CWE-257 - хранение пароля в восстанавливаемом формате)
    salted_password = salt + password
    hashed_password = hashlib.md5(salted_password.encode()).hexdigest()  # НИКОГДА НЕ ИСПОЛЬЗУЙТЕ MD5 для паролей
    return hashed_password

def authenticate(username, password):
    """Проверяет учетные данные пользователя."""
    if username == HARDCODED_USERNAME and password == HARDCODED_PASSWORD:  # CWE-260
        print("Предупреждение: используются жестко закодированные учетные данные!")
        return True

    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                stored_username, stored_hashed_password, stored_salt = line.strip().split(":")
                if username == stored_username:
                    hashed_password = hash_password(password, stored_salt)
                    return hashed_password == stored_hashed_password
        return False
    except FileNotFoundError:
        return False

def change_password(username):
    """Позволяет пользователю сменить свой пароль."""
    new_password = input("Введите новый пароль: ")  # CWE-549: Пароль отображается при вводе + CWE-522 - нет проверки на юзера

    # Проверяем, существует ли пользователь
    try:
        with open(USERS_FILE, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("Ошибка: файл пользователей не найден.")
        return

    found = False
    for i, line in enumerate(lines):
        stored_username, stored_hashed_password, stored_salt = line.strip().split(":")
        if username == stored_username:
            found = True
            salt = secrets.token_hex(16)
            hashed_password = hash_password(new_password, salt) # CWE-522. MD5
            lines[i] = f"{username}:{hashed_password}:{salt}\n"
            print("Пароль будет сохранен в users.txt в виде текста") #CWE-549
            break

    if not found:
        print(f"Пользователь {username} не найден.")
        return

    with open(USERS_FILE, "w") as f:
        f.writelines(lines)
    print("Пароль успешно изменен.")


def main():
    while True:
        print("\nМеню:")
        print("1. Создать пользователя")
        print("2. Войти")
        print("3. Сменить пароль")
        print("4. Выйти")

        choice = input("Выберите действие: ")

        if choice == "1":
            username = input("Введите имя пользователя: ")
            password = input("Введите пароль: ")  # CWE-549: Пароль отображается при вводе
            create_user(username, password)
        elif choice == "2":
            username = input("Введите имя пользователя: ")
            #password = input("Введите пароль: ") #Пароль отображается при вводе. лучше getpass()
            password = getpass.getpass("Введите пароль: ")  # Более безопасно, пароль не отображается
            if authenticate(username, password):
                print("Вход выполнен успешно!")
            else:
                print("Неверное имя пользователя или пароль.")
        elif choice == "3":
            username = input("Введите имя пользователя, ПАРОЛЬ КОТОРОГО ВЫ ХОТИТЕ СМЕНИТЬ: ")
            change_password(username)
        elif choice == "4":
            break
        else:
            print("Неверный выбор. Попробуйте еще раз.")

if __name__ == "__main__":
    main()
