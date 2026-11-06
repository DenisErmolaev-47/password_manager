import os
import pytest
from password_manager import PasswordManager


def test_init_and_unlock(tmp_path):
    """Тест создания мастер-пароля и проверки входа (unlock)."""
    storage = str(tmp_path / "vault.json")
    salt = str(tmp_path / "salt.bin")

    pm = PasswordManager(storage_file=storage, salt_file=salt)
    pm.init_master("master123")

    # С верным паролем должно пустить (True)
    assert pm.unlock("master123") is True
    # С неверным паролем — нет (False)
    assert pm.unlock("wrongpass") is False


def test_crud_operations(tmp_path):
    """Тест добавления, просмотра, получения и удаления записей."""
    storage = str(tmp_path / "vault.json")
    salt = str(tmp_path / "salt.bin")

    pm = PasswordManager(storage_file=storage, salt_file=salt)
    pm.init_master("master123")
    pm.unlock("master123")

    # Добавляем запись
    pm.add_entry("gmail", "test@gmail.com", "mypassword123")

    # Проверяем, что она есть в списке
    entries = pm.list_entries()
    assert "gmail" in entries

    # Проверяем расшифровку логина и пароля
    res = pm.get_entry("gmail")
    assert res is not None
    login, pwd = res
    assert login == "test@gmail.com"
    assert pwd == "mypassword123"

    # Удаляем запись
    assert pm.delete_entry("gmail") is True
    assert "gmail" not in pm.list_entries()


def test_password_generator():
    """Тест генератора случайных паролей."""
    pwd = PasswordManager.generate_password(14)
    assert len(pwd) == 14
    assert isinstance(pwd, str)