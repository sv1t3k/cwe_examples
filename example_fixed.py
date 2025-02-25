import hashlib
import os
import secrets
import getpass
# import bcrypt
from passlib.hash import bcrypt

# Исправлено: Убраны жестко закодированные учетные данные
# HARDCODED_USERNAME = "admin"
# HARDCODED_PASSWORD = "password123"

USERS_FILE = "users_protected.txt"

def create_user(username, password):
    """Создает нового пользователя и сохраняет его данные в файл."""
    salt = bcrypt.gensalt()
    hashed_password = hash_password(password, salt)
    with open(USERS_FILE, "a") as f:
        f.write(f"{username}:{hashed_password.decode()}:{salt.decode()}\n")
    print(f"Пользователь {username} успешно создан.")

def hash_password(password, salt):
    """Хеширует пароль с использованием bcrypt."""  # Исправлено: Используется bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def authenticate(username, password):
    """Проверяет учетные данные пользователя."""
    # Исправлено: Убрана проверка жестко закодированных учетных данных
    # if username == HARDCODED_USERNAME and password == HARDCODED_PASSWORD:
    #     print("Предупреждение: используются жестко закодированные учетные данные!")
    #     return True

    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                stored_username, stored_hashed_password, stored_salt = line.strip().split(":")
                if username == stored_username:
                    hashed_password = bcrypt.hashpw(password.encode('utf-8'), stored_salt.encode('utf-8'))
                    return hashed_password.decode() == stored_hashed_password
        return False
    except FileNotFoundError:
        return False

def change_password(username):
    """Позволяет пользователю сменить свой пароль."""
    username = input("Введите имя пользователя: ")
    password = getpass.getpass("Введите текущий пароль: ")

    if authenticate(username, password): # Введение проверки пользователя для его аутентификации и исправления возможности смены пароля для любого пользователя (CWE-522)
        # Исправлено: Используется getpass для скрытия пароля
        new_password = getpass.getpass("Введите новый пароль: ")  # Исправлено: Пароль не отображается при вводе

        # Проверяем, существует ли пользователь
        try:
            with open(USERS_FILE, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print("Ошибка: файл пользователей не найден.")
            return

        for i, line in enumerate(lines):
            stored_username, stored_hashed_password, stored_salt = line.strip().split(":")
            if username == stored_username:
                salt = bcrypt.gensalt()
                hashed_password = hash_password(new_password, salt)
                lines[i] = f"{username}:{hashed_password.decode()}:{salt.decode()}\n"
                break

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
            # Исправлено: Используется getpass для скрытия пароля
            password = getpass.getpass("Введите пароль: ")  # Исправлено: Пароль не отображается при вводе
            create_user(username, password)
        elif choice == "2":
            username = input("Введите имя пользователя: ")
            # Исправлено: Используется getpass для скрытия пароля
            password = getpass.getpass("Введите пароль: ")  # Исправлено: Пароль не отображается
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
