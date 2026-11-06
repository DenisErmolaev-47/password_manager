import base64
import getpass
import json
import os
import random
import string
from typing import Any, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:
    """Менеджер паролей с шифрованием данных и защитой мастер-паролем."""

    def __init__(
        self, storage_file: str = "vault.json", salt_file: str = "salt.bin"
    ) -> None:
        self.storage_file = storage_file
        self.salt_file = salt_file
        self._key: Optional[bytes] = None

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Генерация ключа шифрования из мастер-пароля и соли."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def init_master(self, password: str) -> None:
        """Создание мастер-пароля при первом запуске."""
        salt = os.urandom(16)
        with open(self.salt_file, "wb") as f:
            f.write(salt)

        key = self._derive_key(password, salt)
        f_crypt = Fernet(key)
        token = f_crypt.encrypt(b"master_check")

        data = {"master_hash": token.decode(), "entries": {}}
        with open(self.storage_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

    def unlock(self, password: str) -> bool:
        """Проверка мастер-пароля и разблокировка хранилища."""
        if not os.path.exists(self.salt_file) or not os.path.exists(
            self.storage_file
        ):
            return False

        with open(self.salt_file, "rb") as f:
            salt = f.read()

        try:
            key = self._derive_key(password, salt)
            f_crypt = Fernet(key)

            with open(self.storage_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            decrypted = f_crypt.decrypt(data["master_hash"].encode())
            if decrypted == b"master_check":
                self._key = key
                return True
        except Exception:
            pass

        return False

    def _load_data(self) -> Dict[str, Any]:
        """Загрузка данных из JSON-файла."""
        if not os.path.exists(self.storage_file):
            return {"master_hash": "", "entries": {}}
        with open(self.storage_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_data(self, data: Dict[str, Any]) -> None:
        """Сохранение данных в JSON-файл."""
        with open(self.storage_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

    def add_entry(self, name: str, login: str, pwd: str) -> None:
        """Добавление новой зашифрованной записи."""
        if not self._key:
            raise ValueError("Хранилище не разблокировано!")

        f_crypt = Fernet(self._key)
        encrypted_login = f_crypt.encrypt(login.encode()).decode()
        encrypted_pwd = f_crypt.encrypt(pwd.encode()).decode()

        data = self._load_data()
        data["entries"][name] = {
            "login": encrypted_login,
            "password": encrypted_pwd,
        }
        self._save_data(data)

    def list_entries(self) -> List[str]:
        """Получение списка названий всех сохраненных записей (без паролей)."""
        data = self._load_data()
        return list(data.get("entries", {}).keys())

    def get_entry(self, name: str) -> Optional[Tuple[str, str]]:
        """Получение логина и пароля по названию записи."""
        if not self._key:
            raise ValueError("Хранилище не разблокировано!")

        data = self._load_data()
        entry = data.get("entries", {}).get(name)
        if not entry:
            return None

        f_crypt = Fernet(self._key)
        login = f_crypt.decrypt(entry["login"].encode()).decode()
        pwd = f_crypt.decrypt(entry["password"].encode()).decode()
        return login, pwd

    def delete_entry(self, name: str) -> bool:
        """Удаление записи по названию."""
        data = self._load_data()
        if name in data.get("entries", {}):
            del data["entries"][name]
            self._save_data(data)
            return True
        return False

    @staticmethod
    def generate_password(length: int = 12) -> str:
        """Генерация надежного пароля."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(random.choice(chars) for _ in range(length))


if __name__ == "__main__":
    pm = PasswordManager()

    # Проверяем, создано ли хранилище (первый ли это запуск)
    if not os.path.exists("vault.json") or not os.path.exists("salt.bin"):
        print("Хранилище не найдено. Давайте создадим мастер-пароль.")
        while True:
            p1 = getpass.getpass("Введите новый мастер-пароль: ")
            p2 = getpass.getpass("Повторите мастер-пароль: ")
            if p1 == p2 and p1:
                pm.init_master(p1)
                pm.unlock(p1)
                print("Мастер-пароль успешно создан!")
                break
            print("Пароли не совпадают или пусты. Попробуйте снова.")
    else:
        print("Вход в менеджер паролей")
        attempts = 3
        while attempts > 0:
            p = getpass.getpass("Введите мастер-пароль: ")
            if pm.unlock(p):
                print("Успешный вход!")
                break
            attempts -= 1
            print(f"Неверный пароль! Осталось попыток: {attempts}")
        else:
            print("Превышено число попыток. Выход.")
            exit(1)

    # Интерактивное консольное меню
    while True:
        print("\n--- МЕНЕДЖЕР ПАРОЛЕЙ ---")
        print("1. Показать список записей")
        print("2. Добавить запись")
        print("3. Получить логин и пароль")
        print("4. Удалить запись")
        print("5. Сгенерировать надежный пароль")
        print("6. Выход")

        choice = input("Выберите пункт меню (1-6): ").strip()

        if choice == "1":
            entries = pm.list_entries()
            print(f"\nСохраненные записи ({len(entries)}):")
            for name in entries:
                print(f" - {name}")

        elif choice == "2":
            name = input("Введите название сервиса/сайта: ").strip()
            login = input("Введите логин/email: ").strip()
            pwd = getpass.getpass("Введите пароль (нажмите Enter для автогенерации): ")
            if not pwd:
                pwd = pm.generate_password()
                print(f"Сгенерирован надежный пароль: {pwd}")
            pm.add_entry(name, login, pwd)
            print(f"Запись '{name}' успешно добавлена!")

        elif choice == "3":
            name = input("Введите название сервиса для поиска: ").strip()
            res = pm.get_entry(name)
            if res:
                found_login, found_pwd = res
                print(f"\n[Найдено]")
                print(f"Логин: {found_login}")
                print(f"Пароль: {found_pwd}")
            else:
                print("Запись с таким названием не найдена.")

        elif choice == "4":
            name = input("Введите название записи для удаления: ").strip()
            if pm.delete_entry(name):
                print(f"Запись '{name}' успешно удалена.")
            else:
                print("Запись не найдена.")

        elif choice == "5":
            length_str = input("Введите длину пароля (по умолчанию 12): ").strip()
            length = int(length_str) if length_str.isdigit() else 12
            new_pwd = pm.generate_password(length)
            print(f"Сгенерированный пароль: {new_pwd}")

        elif choice == "6":
            print("До свидания!")
            break
        else:
            print("Неверный выбор. Введите число от 1 до 6.")