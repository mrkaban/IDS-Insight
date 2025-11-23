# -*- coding: utf-8 -*-
import sys
import ctypes
import locale
import os
import configparser
from PyQt6.QtWidgets import QApplication, QMessageBox, QCheckBox
from PyQt6.QtCore import Qt
from gui import MainWindow
from localization import Translator

def get_system_language():
    """Определяет язык системы современными методами"""
    try:
        # Способ 1: используем getlocale() вместо устаревшего getdefaultlocale()
        lang, _ = locale.getlocale()
        if lang and (lang.startswith('ru_RU') or lang.startswith('ru')):
            return 'ru'
    except Exception:
        pass
    
    # Способ 2: через переменные окружения
    try:
        env_lang = os.environ.get('LANG', '') or os.environ.get('LANGUAGE', '') or os.environ.get('LC_ALL', '')
        if env_lang and ('ru' in env_lang.lower()):
            return 'ru'
    except Exception:
        pass
    
    # Способ 3: для Windows через WinAPI
    try:
        if os.name == 'nt':
            windll = ctypes.windll.kernel32
            # Получаем язык интерфейса пользователя
            lang_id = windll.GetUserDefaultUILanguage()
            # Преобразуем ID языка в строку (например, 1049 -> 'ru_RU')
            lang_name = locale.windows_locale.get(lang_id)
            if lang_name and lang_name.startswith('ru'):
                return 'ru'
    except Exception:
        pass
    
    # По умолчанию английский
    return 'en'

def load_app_settings():
    """Загружает настройки приложения"""
    config = configparser.ConfigParser()
    settings = {
        'language': 'en',
        'language_dialog_disabled': False
    }
    
    if os.path.exists("suricata_gui.ini"):
        try:
            config.read("suricata_gui.ini", encoding='utf-8')
            if 'Settings' in config:
                if 'language' in config['Settings']:
                    settings['language'] = config['Settings']['language']
                if 'language_dialog_disabled' in config['Settings']:
                    settings['language_dialog_disabled'] = config['Settings'].getboolean('language_dialog_disabled')
        except Exception as e:
            print(f"Ошибка загрузки настроек: {e}")
    
    return settings

def save_app_settings(language, disable_dialog=False):
    """Сохраняет настройки языка и диалога"""
    config = configparser.ConfigParser()
    
    # Загружаем существующие настройки, если файл есть
    if os.path.exists("suricata_gui.ini"):
        try:
            config.read("suricata_gui.ini", encoding='utf-8')
        except Exception as e:
            print(f"Ошибка чтения настроек: {e}")
    
    # Создаем секцию Settings, если её нет
    if not config.has_section('Settings'):
        config.add_section('Settings')
    
    # Обновляем настройки языка и диалога
    config['Settings']['language'] = language
    config['Settings']['language_dialog_disabled'] = str(disable_dialog)
    
    # Сохраняем настройки
    try:
        with open("suricata_gui.ini", 'w', encoding='utf-8') as f:
            config.write(f)
    except Exception as e:
        print(f"Ошибка сохранения настроек: {e}")

def show_language_selection_dialog(system_language):
    """Показывает диалог выбора языка интерфейса"""
    if system_language == 'ru':
        title = "Выбор языка интерфейса"
        message = (
            "Язык системы определен как Русский.\n\n"
            "Использовать Русский язык интерфейса приложения?\n"
            "(При выборе 'Нет' будет включен Английский язык, который можно будет изменить в настройках)"
        )
        yes_text = "Да"
        no_text = "Нет"
        dont_ask_text = "Больше не спрашивать"
    else:
        title = "Interface Language Selection"
        message = (
            "System language detected as English.\n\n"
            "Use English interface language?\n"
            "(If you select 'No', Russian language will be enabled, which can be changed in settings)"
        )
        yes_text = "Yes"
        no_text = "No"
        dont_ask_text = "Don't ask again"
    
    msg_box = QMessageBox()
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setIcon(QMessageBox.Icon.Question)
    
    # Добавляем галочку "Больше не спрашивать"
    dont_ask_checkbox = QCheckBox(dont_ask_text)
    msg_box.setCheckBox(dont_ask_checkbox)
    
    # Создаем кнопки с правильными текстами
    yes_button = msg_box.addButton(yes_text, QMessageBox.ButtonRole.YesRole)
    no_button = msg_box.addButton(no_text, QMessageBox.ButtonRole.NoRole)
    
    msg_box.setDefaultButton(yes_button)
    msg_box.exec()
    
    # Определяем выбранный язык
    if msg_box.clickedButton() == yes_button:
        selected_language = system_language  # Использовать язык системы
    else:
        # Возвращаем противоположный язык
        selected_language = 'en' if system_language == 'ru' else 'ru'
    
    return selected_language, dont_ask_checkbox.isChecked()

if __name__ == "__main__":
    # Проверка прав администратора
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, None, 1)
    
    app = QApplication(sys.argv)
    
    # Загружаем настройки приложения
    app_settings = load_app_settings()
    
    # Определяем язык системы
    system_language = get_system_language()
    print(f"Определен язык системы: {system_language}")
    
    # Проверяем, отключен ли диалог выбора языка
    if app_settings['language_dialog_disabled']:
        # Используем сохраненный язык
        selected_language = app_settings['language']
        print(f"Диалог отключен, используется сохраненный язык: {selected_language}")
    else:
        # Показываем диалог выбора языка
        selected_language, disable_dialog = show_language_selection_dialog(system_language)
        print(f"Выбран язык интерфейса: {selected_language}")
        
        # Сохраняем выбор языка и настройку диалога
        save_app_settings(selected_language, disable_dialog)
        print(f"Настройка 'Больше не спрашивать': {disable_dialog}")
    
    # Создаем транслятор с выбранным языком
    translator = Translator(selected_language)

    window = MainWindow(translator)
    window.show()
    sys.exit(app.exec())
    
 # исправил ошибку открытия правила с эмодзи в названи
 # добавил локализацию
 # добавил определение языка при запуске