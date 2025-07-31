# -*- coding: utf-8 -*-
import os
import json
import logging
import traceback
import win32service
import win32serviceutil
import shutil
import socket
import yaml  
from datetime import datetime
from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QApplication,
    QPushButton, QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem,
    QHeaderView, QFileDialog, QMessageBox, QLabel, QComboBox, QLineEdit, QDialog,
    QStatusBar, QSplitter, QAbstractItemView, QMenu, QGroupBox, QFormLayout,
    QCheckBox, QTextEdit, QScrollArea, QButtonGroup, QRadioButton, QPlainTextEdit,
    QListWidget, QProgressDialog, QStyle, QInputDialog, QFrame, 
    QSizePolicy, QGridLayout, QSpinBox, QDateTimeEdit
)
from PyQt6.QtCore import Qt, QTimer, QDateTime
from PyQt6.QtGui import ( QColor, QFont,QPixmap, QIcon, QTextDocument, 
QTextCharFormat, QImage, QMovie)
from manager import SuricataManager
from dialogs import RuleDialog, ServiceDialog
from highlighter import YamlHighlighter, JsonHighlighter
# Для импорта правил
import ctypes
import tempfile
from win32com.shell import shell, shellcon
import win32event
import win32api  # Исправленный импорт
# для работы с источниками правил из интернета
import urllib.request
import tarfile
import zipfile
import configparser
from datetime import datetime

APP_STYLE = """
    QGroupBox {
        font-size: 14px;
        font-weight: bold;
        border: 1px solid #ccc;
        border-radius: 5px;
        margin-top: 1ex;
        padding-top: 10px;
    }
    
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 5px;
        background-color: #f0f0f0;
    }
    
    QTextEdit {
        background-color: #f8f8f8;
        border: 1px solid #ddd;
        border-radius: 3px;
        padding: 5px;
    }
    
    QLabel[accessibleName="author_label"] {
        color: #2c3e50;
        margin-bottom: 10px;
    }
    
    QLabel[accessibleName="website_label"] {
        color: #3498db;
        text-decoration: none;
    }
"""

class MainWindow(QMainWindow):
    """Главное окно приложения"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS Insight - Графический интерфейс к системе обнаружения вторжений Suricata")
        self.setGeometry(100, 100, 1200, 800)
        
        # Проверка необходимых файлов
        self.check_required_files()
        
        # Установка иконки приложения
        if os.path.exists("icon.ico"):
            self.setWindowIcon(QIcon("icon.ico"))
            
        # Применяем стили
        self.setStyleSheet(APP_STYLE)
        
        self.suricata = SuricataManager()
        self.current_rules = {}
        self.config_modified = False
        
        # Добавляем после создания SuricataManager
        self.rule_sources = RuleSources()
        
        # Создаем табы в новом порядке
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Вкладка событий (первая)
        self.alerts_tab = QWidget()
        self.init_alerts_tab()
        self.tabs.addTab(self.alerts_tab, "События")
        
        # Устанавливаем начальные значения времени
        self.set_default_time_filter()
        
        # Вкладка правил
        self.rules_tab = QWidget()
        self.init_rules_tab()
        self.tabs.addTab(self.rules_tab, "Управление правилами")
        
        self.manage_tab = QWidget()
        self.init_manage_tab()
        self.tabs.addTab(self.manage_tab, "Управление Suricata")
        
        self.settings_tab = QWidget()
        self.init_settings_tab()
        self.tabs.addTab(self.settings_tab, "Настройки")
        
        # Добавляем вкладку "О программе"
        self.about_tab = QWidget()
        self.init_about_tab()
        self.tabs.addTab(self.about_tab, "О программе")
        
        # Статус бар
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.update_status()
        
        # Таймер для обновления статуса
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(5000)  # Обновление каждые 5 секунд
        
        # Таймер для обновления событий
        self.events_timer = QTimer()
        self.events_timer.timeout.connect(self.load_alerts)
        
        # Устанавливаем начальное состояние автообновления
        auto_refresh = self.suricata.config.get('auto_refresh', True)
        if isinstance(auto_refresh, str):
            auto_refresh = auto_refresh.lower() == 'true'
        self.auto_refresh_check.setChecked(bool(auto_refresh))
        
        # ЯВНЫЙ ВЫЗОВ ПРИ ЗАПУСКЕ
        self.load_alerts()  # Грузим события сразу при старте
        
        # Если автообновление включено, запускаем таймер
        if auto_refresh and not self.suricata.config.get('show_all_events', False):
            self.events_timer.start(10000)
        
        # Загрузка данных
        self.load_rules()
        self.load_alerts()
        
        # Строим индекс правил
        self.suricata.build_rule_index()
        
        # Проверка службы при запуске
        if not self.suricata.service_exists():
            self.show_service_warning()
            
        # Проверка отсутствующих файлов правил
        self.check_missing_rule_files()
        
    def set_default_time_filter(self):
        """Устанавливает значения по умолчанию для фильтра времени"""
        # Текущее время
        current_time = QDateTime.currentDateTime()
        
        # Начало - текущее время минус 1 час
        start_time = current_time.addSecs(-3600)
        
        # Устанавливаем значения в виджеты
        self.start_datetime.setDateTime(start_time)
        self.end_datetime.setDateTime(current_time)
        
        # Сохраняем в конфиг в правильном формате
        self.suricata.config['start_time'] = start_time.toString(Qt.DateFormat.ISODate)
        self.suricata.config['end_time'] = current_time.toString(Qt.DateFormat.ISODate)
        
        
    def check_required_files(self):
        """Проверяет наличие необходимых файлов"""
        missing_files = []
        if not os.path.exists("icon.ico"):
            missing_files.append("icon.ico")
        if not os.path.exists("cat.png"):
            missing_files.append("cat.png")
        if not os.path.exists("LICENSE.txt"):
            missing_files.append("LICENSE.txt")
        
        if missing_files:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setWindowTitle("Отсутствуют файлы")
            msg.setText("Следующие файлы не найдены в папке приложения:")
            msg.setDetailedText("\n".join(missing_files))
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()
    
    def load_cat_image(self):
        """Загружает и отображает изображение кота с высоким качеством"""
        if os.path.exists("cat.png"):
            try:
                # Загружаем изображение
                pixmap = QPixmap("cat.png")
                
                # Оптимизируем изображение для экрана
                pixmap = pixmap.scaled(
                    pixmap.size(), 
                    Qt.AspectRatioMode.IgnoreAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                
                # Преобразуем в формат, который лучше отображается
                image = pixmap.toImage()
                image = image.convertToFormat(QImage.Format.Format_ARGB32_Premultiplied)
                pixmap = QPixmap.fromImage(image)
                
                # Сохраняем оригинальное изображение для перерисовки
                self.original_pixmap = pixmap
                
                # Устанавливаем изображение
                self.update_image_size()
                
            except Exception as e:
                self.image_label.setText(f"Ошибка загрузки изображения:\n{str(e)}")
                self.image_label.setStyleSheet("color: red; font-weight: bold;")
        else:
            self.image_label.setText("Изображение cat.png не найдено")
            self.image_label.setStyleSheet("color: red; font-weight: bold;")
            
        
    def resizeEvent(self, event):
        """Обрабатывает изменение размера окна"""
        super().resizeEvent(event)
        if hasattr(self, 'original_pixmap'):
            self.update_image_size()
    
    def update_image_size(self):
        """Обновляет размер изображения в соответствии с текущим размером виджета"""
        # Получаем текущий размер виджета
        widget_size = self.image_label.size()
        
        # Масштабируем изображение с сохранением пропорций и высоким качеством
        scaled_pixmap = self.original_pixmap.scaled(
            widget_size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation
        )
        
        self.image_label.setPixmap(scaled_pixmap)
    
        
    def init_about_tab(self):
        """Инициализация вкладки 'О программе'"""
        # Основной макет - горизонтальное расположение
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(20)
        self.about_tab.setLayout(main_layout)
        
        # Левая часть: изображение кота
        image_frame = QFrame()
        image_frame.setFrameShape(QFrame.Shape.StyledPanel)
        image_layout = QVBoxLayout()
        image_layout.setContentsMargins(0, 0, 0, 0)
        
        # Виджет для изображения
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        # Загрузка изображения
        self.load_cat_image()
        
        image_layout.addWidget(self.image_label)
        image_frame.setLayout(image_layout)
        image_frame.setMinimumWidth(350)
        
        # Стиль для рамки изображения
        image_frame.setStyleSheet("""
            QFrame {
                background-color: #f0f0f0;
                border-radius: 8px;
                border: 1px solid #d0d0d0;
            }
            QLabel {
                background-color: #f8f8f8;
                border: none;
            }
        """)
        
        main_layout.addWidget(image_frame, 1)  # Коэффициент растяжения 1
        
        # Правая часть: информация о программе
        info_frame = QFrame()
        info_layout = QVBoxLayout()
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(20)
        info_frame.setLayout(info_layout)
        
        # Верхняя часть: информация об авторе
        author_frame = QGroupBox("Автор")
        author_layout = QVBoxLayout()
        author_layout.setContentsMargins(15, 15, 15, 15)
        author_layout.setSpacing(10)
        
        # Название приложения
        app_name = QLabel("IDS Insight")
        app_name.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        app_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        author_layout.addWidget(app_name)
        
        # Разделитель
        author_layout.addWidget(QLabel(""))
        
        # Информация об авторе
        author_label = QLabel("Разработчик:")
        author_label.setFont(QFont("Arial", 12))
        author_layout.addWidget(author_label)
        
        author_name = QLabel("Алексей Черемых")
        author_name.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        author_name.setStyleSheet("color: #2c3e50;")
        author_layout.addWidget(author_name)
        
        # Сайт
        website_label = QLabel("Официальный сайт:")
        website_label.setFont(QFont("Arial", 12))
        author_layout.addWidget(website_label)
        
        website_url = QLabel()
        website_url.setText('<a href="https://alekseycheremnykh.ru" style="color: #3498db; text-decoration: none; font-size: 14px;">alekseycheremnykh.ru</a>')
        website_url.setOpenExternalLinks(True)
        author_layout.addWidget(website_url)
        
        # Версия программы
        version_label = QLabel("Версия: 1.0")
        version_label.setFont(QFont("Arial", 10))
        version_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        author_layout.addWidget(version_label)
        
        author_frame.setLayout(author_layout)
        info_layout.addWidget(author_frame)
        
        # Нижняя часть: лицензия
        license_frame = QGroupBox("Лицензия")
        license_layout = QVBoxLayout()
        license_layout.setContentsMargins(15, 15, 15, 15)
        
        license_label = QLabel("Лицензионное соглашение:")
        license_label.setFont(QFont("Arial", 10))
        license_layout.addWidget(license_label)
        
        self.license_text = QTextEdit()
        self.license_text.setReadOnly(True)
        self.license_text.setFont(QFont("Consolas", 9))
        
        # Загружаем текст лицензии
        license_content = ""
        if os.path.exists("LICENSE.txt"):
            try:
                with open("LICENSE.txt", "r", encoding="utf-8") as f:
                    license_content = f.read()
            except Exception as e:
                license_content = f"Ошибка загрузки лицензии: {str(e)}"
        else:
            license_content = "Файл лицензии (LICENSE.txt) не найден в папке приложения"
        
        self.license_text.setText(license_content)
        license_layout.addWidget(self.license_text)
        
        license_frame.setLayout(license_layout)
        info_layout.addWidget(license_frame)
        
        info_frame.setLayout(info_layout)
        main_layout.addWidget(info_frame, 2)  # Коэффициент растяжения 2
        
        # Устанавливаем соотношение 1:2 между изображением и информацией
        main_layout.setStretch(0, 1)
        main_layout.setStretch(1, 2)
        
        
    def check_missing_rule_files(self):
        """Проверяет и обрабатывает отсутствующие файлы правил"""
        missing_files = self.suricata.check_rule_files_existence()
        
        if missing_files:
            # Удаляем из конфига
            updated = self.suricata.remove_missing_rule_files_from_config(missing_files)
            
            # Показываем уведомление
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setWindowTitle("Обнаружены отсутствующие файлы правил")
            
            if updated:
                msg.setText("Следующие файлы правил отсутствуют и были удалены из конфигурации:")
            else:
                msg.setText("Следующие файлы правил отсутствуют:")
                
            # Добавляем подробности
            details = "\n".join(missing_files)
            msg.setDetailedText(details)
            
            # Основное сообщение
            main_text = msg.text()
            msg.setText(f"{main_text}\n\nПодробности см. ниже.")
            
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()

    
    
    def resize_columns_to_content(self, widget, max_width=400):
        """Автоматическая подгонка ширины колонок с ограничением"""
        if isinstance(widget, QTableWidget):
            widget.resizeColumnsToContents()
            header = widget.horizontalHeader()
            for i in range(header.count()):
                if header.sectionSize(i) > max_width:
                    header.resizeSection(i, max_width)
        elif isinstance(widget, QTreeWidget):
            header = widget.header()
            for i in range(header.count()):
                widget.resizeColumnToContents(i)
                if header.sectionSize(i) > max_width:
                    header.resizeSection(i, max_width)
    
    def show_service_warning(self):
        """Показывает предупреждение о недоступности службы"""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Служба не найдена")
        msg.setText(f"Служба Suricata '{self.suricata.service_name}' не найдена!")
        msg.setInformativeText("Пожалуйста, настройте правильное имя службы.")
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()
    
    def init_settings_tab(self):
        """Инициализация вкладки настроек"""
        layout = QVBoxLayout()
        
        # Панель инструментов
        toolbar = QHBoxLayout()
        
        self.load_config_btn = QPushButton("Загрузить конфиг")
        self.load_config_btn.clicked.connect(self.load_config)
        toolbar.addWidget(self.load_config_btn)
        
        self.save_config_btn = QPushButton("Сохранить конфиг")
        self.save_config_btn.clicked.connect(self.save_config)
        toolbar.addWidget(self.save_config_btn)
        
        self.validate_config_btn = QPushButton("Проверить конфиг")
        self.validate_config_btn.clicked.connect(self.validate_config)
        toolbar.addWidget(self.validate_config_btn)
        
        self.apply_config_btn = QPushButton("Применить конфиг")
        self.apply_config_btn.clicked.connect(self.apply_config)
        toolbar.addWidget(self.apply_config_btn)
        
        layout.addLayout(toolbar)
        
        # Статус конфигурации
        self.config_status = QLabel("Статус: Конфигурация не загружена")
        self.config_status.setFont(QFont("Arial", 10))
        layout.addWidget(self.config_status)
        
        # Добавляем поле поиска
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Поиск:"))
        self.config_search_edit = QLineEdit()
        self.config_search_edit.setPlaceholderText("Поиск в конфигурации...")
        self.config_search_edit.textChanged.connect(self.filter_config)
        search_layout.addWidget(self.config_search_edit)
        
        # Добавляем под тулбаром
        layout.insertLayout(1, search_layout)
        
        # Редактор конфигурации
        self.config_editor = QPlainTextEdit()
        self.config_editor.setFont(QFont("Consolas", 10))
        self.config_editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.config_editor.textChanged.connect(self.config_modified_handler)
        
        # Подсветка синтаксиса YAML
        self.highlighter = YamlHighlighter(self.config_editor.document())
        
        layout.addWidget(self.config_editor)
        
        # Группа настроек
        settings_group = QGroupBox("Основные настройки")
        form_layout = QFormLayout()
        
        self.suricata_path_edit = QLineEdit(self.suricata.config['suricata_path'])
        form_layout.addRow("Путь к Suricata:", self.suricata_path_edit)
        
        self.rules_dir_edit = QLineEdit(self.suricata.config['rules_dir'])
        form_layout.addRow("Каталог правил:", self.rules_dir_edit)
        
        self.eve_log_edit = QLineEdit(self.suricata.config['eve_log'])
        form_layout.addRow("Файл логов (eve.json):", self.eve_log_edit)
        
        self.backup_dir_edit = QLineEdit(self.suricata.config['backup_dir'])
        form_layout.addRow("Каталог резервных копий:", self.backup_dir_edit)
        
        save_settings_btn = QPushButton("Сохранить настройки")
        save_settings_btn.clicked.connect(self.save_settings)
        form_layout.addRow(save_settings_btn)
        
        settings_group.setLayout(form_layout)
        layout.addWidget(settings_group)
        
        self.settings_tab.setLayout(layout)
        
        # Загружаем конфиг при открытии вкладки
        self.tabs.currentChanged.connect(self.on_tab_changed)
    
    def filter_config(self):
        """Фильтрует конфигурацию по поисковому запросу"""
        search_text = self.config_search_edit.text().lower()
        if not search_text:
            # Показать все строки
            for i in range(self.config_editor.document().blockCount()):
                block = self.config_editor.document().findBlockByNumber(i)
                self.config_editor.setExtraSelections([])
            return
            
        # Создаем выделения для найденных совпадений
        extra_selections = []
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor(255, 255, 0))  # Желтый фон
        
        # Ищем по всему документу
        cursor = self.config_editor.document().find(search_text, 0, 
                                                   QTextDocument.FindFlag(0))  # Case insensitive
        
        while not cursor.isNull():
            # Создаем выделение для найденного текста
            selection = QTextEdit.ExtraSelection()
            selection.format = highlight_format
            selection.cursor = cursor
            extra_selections.append(selection)
            
            # Переходим к следующему совпадению
            cursor = self.config_editor.document().find(
                search_text, cursor.position(), 
                QTextDocument.FindFlag(0))
        
        # Применяем выделения
        self.config_editor.setExtraSelections(extra_selections)
        
        # Прокручиваем к первому совпадению
        if extra_selections:
            self.config_editor.setTextCursor(extra_selections[0].cursor)
    
    def on_tab_changed(self, index):
        """Обработчик смены вкладки"""
        if self.tabs.tabText(index) == "Настройки":
            self.load_config()
    
    def config_modified_handler(self):
        """Обработчик изменения конфигурации"""
        self.config_modified = True
        self.config_status.setText("Статус: Конфигурация изменена (не сохранена)")
    
    def load_config(self):
        """Загружает конфигурацию Suricata в редактор"""
        try:
            config_text = self.suricata.load_config()
            self.config_editor.setPlainText(config_text)
            self.config_modified = False
            self.config_status.setText("Статус: Конфигурация загружена")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка загрузки конфигурации: {str(e)}")
            self.config_status.setText("Статус: Ошибка загрузки конфигурации")
    
    def save_config(self):
        """Сохраняет конфигурацию Suricata в файл"""
        if not self.config_modified:
            QMessageBox.information(self, "Информация", "Конфигурация не изменена")
            return
        # После сохранения проверяем файлы правил
        self.check_missing_rule_files()
            
        config_text = self.config_editor.toPlainText()
        
        # Проверяем валидность перед сохранением
        valid, message = self.suricata.validate_config(config_text)
        if not valid:
            reply = QMessageBox.question(
                self,
                "Ошибка валидации",
                f"{message}\n\nВсё равно сохранить?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return
        
        if self.suricata.save_config(config_text):
            self.config_modified = False
            self.config_status.setText("Статус: Конфигурация сохранена")
            QMessageBox.information(self, "Успех", "Конфигурация успешно сохранена!")
        else:
            QMessageBox.critical(self, "Ошибка", "Ошибка сохранения конфигурации")
    
    def validate_config(self):
        """Проверяет валидность конфигурации"""
        config_text = self.config_editor.toPlainText()
        valid, message = self.suricata.validate_config(config_text)
        
        if valid:
            QMessageBox.information(self, "Успех", "Конфигурация валидна!")
            self.config_status.setText("Статус: Конфигурация валидна")
        else:
            QMessageBox.critical(self, "Ошибка", message)
            self.config_status.setText("Статус: Ошибка в конфигурации")
    
    def apply_config(self):
        """Применяет конфигурацию и перезапускает Suricata"""
        if self.config_modified:
            reply = QMessageBox.question(
                self,
                "Сохранение конфигурации",
                "Конфигурация была изменена. Сохранить перед применением?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.save_config()
            elif reply == QMessageBox.StandardButton.Cancel:
                return
        
        try:
            if self.suricata.restart_suricata():
                QMessageBox.information(self, "Успех", "Suricata успешно перезапущена с новой конфигурацией!")
            else:
                QMessageBox.critical(self, "Ошибка", "Ошибка перезапуска Suricata")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка перезапуска Suricata: {str(e)}")
    
    def save_settings(self):
        """Сохраняет основные настройки приложения"""
        new_settings = {
            'suricata_path': self.suricata_path_edit.text(),
            'rules_dir': self.rules_dir_edit.text(),
            'eve_log': self.eve_log_edit.text(),
            'backup_dir': self.backup_dir_edit.text()
        }
        
        # Проверка существования путей
        errors = []
        for key, path in new_settings.items():
            if not os.path.exists(path):
                errors.append(f"Путь не существует: {path}")
        
        if errors:
            QMessageBox.critical(self, "Ошибка", "\n".join(errors))
            return
        
        # Обновляем настройки в менеджере
        self.suricata.config.update(new_settings)
        
        # Сохраняем в файл настроек
        config = configparser.ConfigParser()
        config['Settings'] = new_settings
        
        try:
            with open("suricata_gui.ini", 'w', encoding='utf-8') as f:
                config.write(f)
            
            self.suricata.rules_dir = new_settings['rules_dir']
            self.suricata.eve_log = new_settings['eve_log']
            self.suricata.backup_dir = new_settings['backup_dir']
            self.suricata.drop_rules = os.path.join(
                new_settings['rules_dir'], 
                self.suricata.config['drop_rules']
            )
            
            # Проверяем drop-правила
            self.suricata.ensure_drop_rules_in_config()
            
            # Перезагружаем правила
            self.load_rules()
            
            QMessageBox.information(self, "Успех", "Настройки успешно сохранены!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка сохранения настроек: {str(e)}")
            
        
    def init_rules_tab(self):
        """Инициализация вкладки управления правилами"""
        
        layout = QVBoxLayout()
        
        # Панель инструментов
        toolbar = QHBoxLayout()
        
        self.import_btn = QPushButton("Импорт правил")
        self.import_btn.clicked.connect(self.import_rules)
        toolbar.addWidget(self.import_btn)
        
        self.refresh_btn = QPushButton("Обновить")
        self.refresh_btn.clicked.connect(self.load_rules)
        toolbar.addWidget(self.refresh_btn)
        
        self.apply_btn = QPushButton("Применить изменения")
        self.apply_btn.clicked.connect(self.apply_rule_changes)
        toolbar.addWidget(self.apply_btn)
        
        self.backup_btn = QPushButton("Создать резервную копию")
        self.backup_btn.clicked.connect(self.create_backup)
        toolbar.addWidget(self.backup_btn)
        
        # Добавляем новые кнопки в toolbar
        self.update_rules_btn = QPushButton("Обновить правила")
        self.update_rules_btn.clicked.connect(self.update_rules_from_sources)
        toolbar.addWidget(self.update_rules_btn)
        
        self.manage_sources_btn = QPushButton("Управление источниками")
        self.manage_sources_btn.clicked.connect(self.manage_rule_sources)
        toolbar.addWidget(self.manage_sources_btn)
        
        layout.addLayout(toolbar)
        
        # Добавляем поиск по правилам
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Поиск правил:"))
        
        self.rule_search_edit = QLineEdit()
        self.rule_search_edit.setPlaceholderText("Поиск по всем правилам...")
        self.rule_search_edit.textChanged.connect(self.filter_rules)
        search_layout.addWidget(self.rule_search_edit)
        
        layout.addLayout(search_layout)  # Добавить после toolbar
        
        # Дерево правил
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        self.rule_files_tree = QTreeWidget()
        self.rule_files_tree.setHeaderLabel("Файлы правил")
        self.rule_files_tree.itemSelectionChanged.connect(self.on_rule_file_selected)
        
        # Добавим контекстное меню для файлов правил
        self.rule_files_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.rule_files_tree.customContextMenuRequested.connect(self.show_rule_file_menu)
        
        self.rules_tree = QTreeWidget()
        self.rules_tree.setHeaderLabels(["Правило", "SID", "Статус"])
        self.rules_tree.itemDoubleClicked.connect(self.show_rule_details)
        
        # Добавляем контекстное меню для правил
        self.rules_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.rules_tree.customContextMenuRequested.connect(self.show_rule_context_menu)
            
        
        splitter.addWidget(self.rule_files_tree)
        splitter.addWidget(self.rules_tree)
        splitter.setSizes([200, 600])
        
        layout.addWidget(splitter)
        self.rules_tab.setLayout(layout)
        
    def filter_rules(self, text):
        """Фильтрует правила по поисковому запросу"""
        search_text = text.strip().lower()
        self.rules_tree.clear()
        
        if not search_text:
            # Если поиск пуст, показываем текущий выбранный файл
            self.on_rule_file_selected()
            return
            
        # Ищем во всех файлах правил
        rule_files = self.suricata.get_rule_files()
        for filename in rule_files:
            rules = self.suricata.parse_rules(filename)
            file_has_matches = False
            file_item = None
            
            for rule in rules:
                # Проверяем совпадение в различных полях правила
                if (search_text in rule['msg'].lower() or 
                    search_text in rule['sid'].lower() or 
                    search_text in rule['raw'].lower()):
                    
                    if not file_item:
                        file_item = QTreeWidgetItem([filename])
                        file_item.setData(0, Qt.ItemDataRole.UserRole, filename)
                        self.rules_tree.addTopLevelItem(file_item)
                        file_has_matches = True
                    
                    # Создаем элемент правила
                    rule_item = QTreeWidgetItem([rule['msg'], rule['sid'], 
                                               "Включено" if rule['enabled'] else "Отключено"])
                    rule_item.setData(0, Qt.ItemDataRole.UserRole, rule)
                    
                    if rule['enabled']:
                        rule_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
                        for col in range(3):
                            rule_item.setForeground(col, QColor(0, 0, 0))
                    else:
                        rule_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
                        for col in range(3):
                            rule_item.setForeground(col, QColor(150, 150, 150))
                    
                    file_item.addChild(rule_item)
            
            if file_has_matches:
                file_item.setExpanded(True)
    
    
    def show_rule_context_menu(self, pos):
        """Показывает контекстное меню для правила"""
        item = self.rules_tree.itemAt(pos)
        if not item:
            return
            
        rule_data = item.data(0, Qt.ItemDataRole.UserRole)
        if not rule_data:
            return
            
        # Создаем меню
        menu = QMenu()
        
        # Действия в зависимости от текущего состояния правила
        if rule_data['enabled']:
            disable_action = menu.addAction("Отключить правило")
            disable_action.triggered.connect(lambda: self.toggle_rule_action(item, False))
        else:
            enable_action = menu.addAction("Включить правило")
            enable_action.triggered.connect(lambda: self.toggle_rule_action(item, True))
        
        # Добавляем действие для изменения действия правила
        change_action = menu.addAction("Изменить действие...")
        change_action.triggered.connect(lambda: self.change_rule_action(item))
        
        # Добавляем действие для редактирования
        edit_action = menu.addAction("Редактировать правило")
        edit_action.triggered.connect(lambda: self.edit_rule_action(item))
        
        # Показываем меню
        menu.exec(self.rules_tree.viewport().mapToGlobal(pos))
    
    def change_rule_action(self, item):
        """Изменяет действие для правила"""
        rule_data = item.data(0, Qt.ItemDataRole.UserRole)
        
        # Получаем текущее действие
        parts = rule_data['raw'].split()
        current_action = parts[0] if rule_data['enabled'] else parts[0].lstrip('#')
        
        # Диалог выбора действия
        actions = ["alert", "drop", "reject", "pass"]
        
        # Определяем текущий индекс
        try:
            current_idx = actions.index(current_action)
        except ValueError:
            current_idx = 0
        
        action, ok = QInputDialog.getItem(
            self, 
            "Изменение действия правила", 
            f"Выберите действие для правила SID {rule_data['sid']}:",
            actions, 
            current=current_idx,  # ИСПРАВЛЕНО: используем 'current' вместо 'currentIndex'
            editable=False
        )
        
        if not ok or action == current_action:
            return
            
        # Создаем новую версию правила
        new_rule = rule_data['raw']
        
        if rule_data['enabled']:
            # Заменяем первое слово
            parts = new_rule.split()
            parts[0] = action
            new_rule = ' '.join(parts)
        else:
            # Убираем комментарий, заменяем действие и снова комментируем
            new_rule = new_rule.lstrip('#').lstrip()
            parts = new_rule.split()
            parts[0] = action
            new_rule = '# ' + ' '.join(parts)
        
        # Обновляем правило
        new_rule_data = rule_data.copy()
        new_rule_data['raw'] = new_rule
        
        if self.suricata.replace_rule(rule_data, new_rule_data):
            QMessageBox.information(self, "Успех", "Действие правила успешно изменено!")
            # Обновляем отображение
            self.on_rule_file_selected()
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось изменить действие правила")
     
    def toggle_rule_action(self, item, enable):
        """Включает/выключает правило через контекстное меню"""
        rule_data = item.data(0, Qt.ItemDataRole.UserRole)
        
        if self.suricata.toggle_rule(rule_data, enable):
            # Обновляем данные правила
            rule_data['enabled'] = enable
            
            # Обновляем данные элемента
            item.setData(0, Qt.ItemDataRole.UserRole, rule_data)
            
            # Обновляем отображение элемента
            if enable:
                for col in range(3):
                    item.setForeground(col, QColor(0, 0, 0))
                item.setText(2, "Включено")
                item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
            else:
                for col in range(3):
                    item.setForeground(col, QColor(150, 150, 150))
                item.setText(2, "Отключено")
                item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
                
            # ОБНОВЛЯЕМ ПРАВИЛО В ТЕКУЩИХ СОБЫТИЯХ
            self.update_rule_in_events(rule_data)
                
            QMessageBox.information(self, "Успех", "Статус правила успешно изменен!")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось изменить статус правила")
    
    def update_rule_in_events(self, updated_rule):
        """Обновляет правило в текущих событиях"""
        for event in self.current_events:
            if event.get('sid') == updated_rule['sid']:
                event['action'] = 'disabled' if not updated_rule['enabled'] else updated_rule['action']
        
    
    
    
    def edit_rule_action(self, item):
        """Открывает диалог редактирования для правила"""
        rule_data = item.data(0, Qt.ItemDataRole.UserRole)
        self.show_rule_details(item, 0)  # 0 - колонка, но не используется
    
    def show_rule_file_menu(self, pos):
        """Контекстное меню для файлов правил"""
        item = self.rule_files_tree.itemAt(pos)
        if not item:
            return
            
        filename = item.data(0, Qt.ItemDataRole.UserRole)
        menu = QMenu()
        
        # Определим текущее состояние файла
        rules = self.suricata.parse_rules(filename)
        enabled_rules = sum(1 for r in rules if r['enabled'])
        file_enabled = enabled_rules > 0
        
        # Добавим действия в меню
        enable_action = menu.addAction("Включить все правила")
        disable_action = menu.addAction("Отключить все правила")
        menu.addSeparator()
        delete_action = menu.addAction("Удалить файл правил")
        
        action = menu.exec(self.rule_files_tree.mapToGlobal(pos))
        
        if action == enable_action:
            self.toggle_rule_file(filename, True)
        elif action == disable_action:
            self.toggle_rule_file(filename, False)
        elif action == delete_action:
            self.delete_rule_file(filename)
            
    def manage_rule_sources(self):
        """Открывает диалог управления источниками правил"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Управление источниками правил")
        dialog.setGeometry(400, 400, 600, 400)
        
        layout = QVBoxLayout()
        
        # Список источников
        self.sources_list = QListWidget()
        for source in self.rule_sources.sources:
            self.sources_list.addItem(f"{source['name']} ({source['url']})")
        layout.addWidget(self.sources_list)
        
        # Кнопки управления
        btn_layout = QHBoxLayout()
        
        add_btn = QPushButton("Добавить")
        add_btn.clicked.connect(lambda: self.add_rule_source(dialog))
        btn_layout.addWidget(add_btn)
        
        remove_btn = QPushButton("Удалить")
        remove_btn.clicked.connect(self.remove_rule_source)
        btn_layout.addWidget(remove_btn)
        
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        dialog.setLayout(layout)
        dialog.exec()
    
    def add_rule_source(self, parent_dialog):
        """Добавляет новый источник правил"""
        dialog = QDialog(parent_dialog)
        dialog.setWindowTitle("Добавить источник")
        dialog.setGeometry(500, 500, 400, 200)
        
        layout = QFormLayout()
        
        name_edit = QLineEdit()
        url_edit = QLineEdit()
        
        layout.addRow("Название:", name_edit)
        layout.addRow("URL:", url_edit)
        
        btn_layout = QHBoxLayout()
        
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(ok_btn)
        
        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(dialog.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addRow(btn_layout)
        dialog.setLayout(layout)
        
        if dialog.exec():
            name = name_edit.text().strip()
            url = url_edit.text().strip()
            
            if name and url:
                self.rule_sources.add_source(name, url)
                self.sources_list.addItem(f"{name} ({url})")
    
    def remove_rule_source(self):
        """Удаляет выбранный источник"""
        selected = self.sources_list.currentRow()
        if selected >= 0:
            self.rule_sources.remove_source(selected)
            self.sources_list.takeItem(selected)
    
    def update_rules_from_sources(self):
        """Обновляет правила из всех источников с обработкой прав доступа"""
    
        if not self.rule_sources.sources:
            QMessageBox.information(self, "Информация", "Нет источников для обновления")
            return
        
        # ПРЕДУПРЕЖДЕНИЕ О СБРОСЕ НАСТРОЕК
        reply = QMessageBox.question(
            self,
            "Подтверждение обновления",
            "Внимание! При обновлении правил все локальные изменения (отключенные правила,\n"
            "измененные действия) будут сброшены. Вы уверены, что хотите продолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Создаем диалог прогресса
        progress = QProgressDialog("Обновление правил...", "Отмена", 0, len(self.rule_sources.sources) + 2, self)
        progress.setWindowTitle("Обновление правил")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        
        success_count = 0
        error_count = 0
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        
        # Создаем временную директорию для загрузки
        temp_dir = tempfile.mkdtemp()
        files_to_copy = []  # Список файлов для копирования
        downloaded_files = []  # Имена скачанных файлов правил
        
        try:
            # Этап 1: Скачивание и подготовка файлов
            for i, source in enumerate(self.rule_sources.sources):
                progress.setLabelText(f"Загрузка: {source['name']}\nURL: {source['url']}")
                progress.setValue(i)
                
                if progress.wasCanceled():
                    break
                
                try:
                    # Скачиваем и распаковываем во временную директорию
                    source_temp_dir = os.path.join(temp_dir, f"source_{i}")
                    os.makedirs(source_temp_dir, exist_ok=True)
                    
                    files = self.rule_sources.download_and_extract(source['url'], source_temp_dir)
                    if files:
                        # Добавляем файлы в общий список
                        files_to_copy.extend(files)
                        # Сохраняем только имена файлов
                        downloaded_files.extend([os.path.basename(f) for f in files])
                        success_count += 1
                    else:
                        error_count += 1
                except Exception as e:
                    logging.error(f"Ошибка обработки {source['url']}: {str(e)}")
                    error_count += 1
            
            # Если нет файлов для копирования, выходим
            if not files_to_copy:
                progress.close()
                QMessageBox.information(
                    self,
                    "Обновление завершено",
                    f"Скачано источников: {success_count}\nОшибок: {error_count}\nНет файлов для копирования"
                )
                return
            
            # Этап 2: Копирование файлов
            progress.setLabelText("Копирование файлов...")
            progress.setValue(len(self.rule_sources.sources) + 1)
            
            if is_admin:
                # Если есть права администратора - копируем напрямую
                for file_path in files_to_copy:
                    filename = os.path.basename(file_path)
                    dest_path = os.path.join(self.suricata.rules_dir, filename)
                    shutil.copy(file_path, dest_path)
            else:
                # Создаем пакетный файл для копирования
                bat_content = "@echo off\n"
                for file_path in files_to_copy:
                    filename = os.path.basename(file_path)
                    dest_path = os.path.join(self.suricata.rules_dir, filename)
                    # Команда для копирования с перезаписью
                    bat_content += f'copy /Y "{file_path}" "{dest_path}" > nul\n'
                bat_content += "exit 0\n"
                
                bat_path = os.path.join(temp_dir, "copy_rules.bat")
                with open(bat_path, 'w') as bat_file:
                    bat_file.write(bat_content)
                
                # Запускаем пакетный файл с правами администратора
                process_info = shell.ShellExecuteEx(
                    fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                    lpVerb='runas',
                    lpFile=bat_path,
                    nShow=0
                )
                
                # Ждем завершения процесса копирования
                win32event.WaitForSingleObject(process_info['hProcess'], -1)
                win32api.CloseHandle(process_info['hProcess'])
            
            # Этап 3: Обновление конфигурации Suricata
            progress.setLabelText("Обновление конфигурации...")
            progress.setValue(len(self.rule_sources.sources) + 2)
            
            # Загружаем текущую конфигурацию
            config_yaml = self.suricata.load_config()
            
            try:
                # Парсим YAML-конфигурацию
                config = yaml.safe_load(config_yaml)
                if config is None:
                    config = {}
                
                # Инициализируем список файлов правил, если его нет
                if 'rule-files' not in config:
                    config['rule-files'] = []
                
                # Получаем текущий список файлов правил
                current_rule_files = config['rule-files']
                
                # Добавляем новые файлы, которых еще нет в конфигурации
                added_files = []
                for filename in downloaded_files:
                    # Проверяем, что это файл правил и его еще нет в конфиге
                    if filename.endswith('.rules') and filename not in current_rule_files:
                        current_rule_files.append(filename)
                        added_files.append(filename)
                
                # Если были добавлены новые файлы, сохраняем конфигурацию
                if added_files:
                    config['rule-files'] = current_rule_files
                    new_config_yaml = yaml.dump(config, default_flow_style=False, sort_keys=False)
                    
                    # Сохраняем обновленный конфиг
                    self.suricata.save_config(new_config_yaml)
                    
                    logging.info(f"Добавлены новые файлы правил в конфиг: {', '.join(added_files)}")
            
            except yaml.YAMLError as e:
                logging.error(f"Ошибка разбора конфигурации YAML: {str(e)}")
            except Exception as e:
                logging.error(f"Ошибка обновления конфигурации: {str(e)}")
        
        except Exception as e:
            logging.error(f"Ошибка обновления правил: {str(e)}")
            QMessageBox.critical(self, "Ошибка", f"Ошибка обновления правил: {str(e)}")
        finally:
            # Удаляем временную директорию
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as e:
                logging.error(f"Ошибка удаления временной директории: {str(e)}")
            progress.close()
        
        # Перезагружаем правила
        self.load_rules()
        
        QMessageBox.information(
            self,
            "Обновление завершено",
            f"Успешно обработано источников: {success_count}\n"
            f"Ошибок: {error_count}\n"
            f"Скопировано файлов: {len(files_to_copy)}\n"
            f"Добавлено в конфиг: {len(added_files) if 'added_files' in locals() else 0}"
        )
        
    def toggle_rule_file(self, filename, enable):
        """Включает/выключает файл правил"""
        if self.suricata.toggle_rule_file(filename, enable):
            self.load_rules()
            QMessageBox.information(
                self, 
                "Успех", 
                f"Все правила в '{filename}' {'включены' if enable else 'отключены'}"
            )
        else:
            QMessageBox.critical(
                self, 
                "Ошибка", 
                f"Не удалось {'включить' if enable else 'отключить'} правила в '{filename}'"
            )
    
    def delete_rule_file(self, filename):
        """Удаляет файл правил"""
        reply = QMessageBox.question(
            self,
            "Подтверждение удаления",
            f"Вы уверены, что хотите удалить '{filename}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                filepath = os.path.join(self.suricata.rules_dir, filename)
                os.remove(filepath)
                self.load_rules()
                QMessageBox.information(self, "Успех", f"Файл '{filename}' удален")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка при удалении файла: {str(e)}\n{traceback.format_exc()}")
    
    def rule_state_changed(self, item, column):
        """Обработчик изменения состояния правила"""
        if column != 2:  # Только для колонки Status
            return
            
        rule_data = item.data(0, Qt.ItemDataRole.UserRole)
        enable = item.checkState(2) == Qt.CheckState.Checked
        
        if self.suricata.toggle_rule(rule_data, enable):
            # Обновляем цвет текста
            if enable:
                for col in range(2):  # Для колонок Rule и SID
                    item.setForeground(col, QColor(0, 0, 0))
            else:
                for col in range(2):
                    item.setForeground(col, QColor(150, 150, 150))
        else:
            # Восстанавливаем предыдущее состояние при ошибке
            item.setCheckState(2, Qt.CheckState.Checked if not enable else Qt.CheckState.Unchecked)
    
    def update_events_limit(self, value):
        """Обновляет лимит отображаемых событий"""
        self.suricata.config['events_limit'] = value
        self.save_app_settings()
        self.load_alerts()
        
    def save_app_settings(self):
        """Сохраняет настройки приложения в файл"""
        config = configparser.ConfigParser()
        config['Settings'] = {
            'suricata_path': self.suricata.config['suricata_path'],
            'rules_dir': self.suricata.config['rules_dir'],
            'eve_log': self.suricata.config['eve_log'],
            'backup_dir': self.suricata.config['backup_dir'],
            'events_limit': str(self.suricata.config.get('events_limit', 1000)),
            'show_all_events': str(self.suricata.config.get('show_all_events', False)),
            'time_filter_enabled': str(self.suricata.config.get('time_filter_enabled', False)),
            'start_time': self.suricata.config.get('start_time', ''),
            'end_time': self.suricata.config.get('end_time', ''),
            'auto_refresh': str(self.auto_refresh_check.isChecked())
        }
        
        try:
            with open("suricata_gui.ini", 'w') as f:
                config.write(f)
        except Exception as e:
            logging.error(f"Ошибка сохранения настроек приложения: {str(e)}")
        
    
    def init_alerts_tab(self):
        """Инициализация вкладки просмотра событий"""
        layout = QVBoxLayout()
        
        # Панель инструментов
        toolbar = QHBoxLayout()
        
        self.refresh_alerts_btn = QPushButton("Обновить события")
        self.refresh_alerts_btn.clicked.connect(self.load_alerts)
        toolbar.addWidget(self.refresh_alerts_btn)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Все события", "Только алерты", "DNS события", "TLS события"])
        self.filter_combo.currentIndexChanged.connect(self.load_alerts)
        toolbar.addWidget(self.filter_combo)
        
        # Добавляем элемент управления для лимита событий
        toolbar.addWidget(QLabel("Событий:"))
        self.events_limit_spin = QSpinBox()
        self.events_limit_spin.setMinimum(100)
        self.events_limit_spin.setMaximum(100000)
        self.events_limit_spin.setValue(self.suricata.config['events_limit'])
        self.events_limit_spin.valueChanged.connect(self.update_events_limit)
        toolbar.addWidget(self.events_limit_spin)
        
        # Галочка "Все"
        self.all_events_check = QCheckBox("Все события")
        self.all_events_check.setChecked(self.suricata.config['show_all_events'])
        self.all_events_check.stateChanged.connect(self.toggle_all_events)
        toolbar.addWidget(self.all_events_check)
        
        # Галочка "Автообновление"
        self.auto_refresh_check = QCheckBox("Автообновление")
        self.auto_refresh_check.setChecked(True)  # По умолчанию включено
        self.auto_refresh_check.stateChanged.connect(self.toggle_auto_refresh)
        toolbar.addWidget(self.auto_refresh_check)
        
        # Кнопка "Обновить сейчас"
        self.refresh_now_btn = QPushButton("Обновить сейчас")
        self.refresh_now_btn.clicked.connect(self.load_alerts)
        toolbar.addWidget(self.refresh_now_btn)
        
        # Фильтр по времени
        time_filter_group = QGroupBox("Фильтр по времени")
        time_layout = QHBoxLayout()
        
        # Кнопка "Текущий час"
        self.last_hour_btn = QPushButton("Текущий час")
        self.last_hour_btn.clicked.connect(self.set_last_hour_filter)
        time_layout.addWidget(self.last_hour_btn)
        
        time_layout.addWidget(QLabel("С:"))
        
        # Виджет начального времени
        self.start_datetime = QDateTimeEdit()
        self.start_datetime.setDisplayFormat("dd.MM.yyyy HH:mm:ss")
        self.start_datetime.setCalendarPopup(True)
        self.start_datetime.setDateTime(QDateTime.currentDateTime().addSecs(-3600))
        self.start_datetime.setFixedWidth(150)  # Фиксированная ширина
        time_layout.addWidget(self.start_datetime)

        time_layout.addWidget(QLabel("По:"))  # ДОБАВЛЕНО: метка для конечного времени
        self.end_datetime = QDateTimeEdit()
        self.end_datetime.setDisplayFormat("dd.MM.yyyy HH:mm:ss")
        self.end_datetime.setCalendarPopup(True)
        self.end_datetime.setDateTime(QDateTime.currentDateTime())  # Текущее время
        self.end_datetime.setFixedWidth(150)
        time_layout.addWidget(self.end_datetime)
        
        self.apply_time_filter_btn = QPushButton("Применить")
        self.apply_time_filter_btn.clicked.connect(self.apply_time_filter)
        time_layout.addWidget(self.apply_time_filter_btn)
        
        self.clear_time_filter_btn = QPushButton("Сбросить")
        self.clear_time_filter_btn.clicked.connect(self.clear_time_filter)
        time_layout.addWidget(self.clear_time_filter_btn)
        
        time_filter_group.setLayout(time_layout)
        layout.addWidget(time_filter_group)
        
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск событий...")
        self.search_edit.textChanged.connect(self.filter_alerts)
        toolbar.addWidget(self.search_edit)
        
        layout.addLayout(toolbar)
        
        time_layout.addStretch(1)
        
        # Таблица событий
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(9)  # Увеличили количество колонок
        self.alerts_table.setHorizontalHeaderLabels([
            "Время", "Тип события", "Сигнатура", "Источник", 
            "Назначение", "Протокол", "Важность", "Действие", "Детали"
        ])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.alerts_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.alerts_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.alerts_table.cellDoubleClicked.connect(self.show_alert_details)
        self.alerts_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.alerts_table.customContextMenuRequested.connect(self.show_alert_context_menu)
        
        
        layout.addWidget(self.alerts_table)
        self.alerts_tab.setLayout(layout)
        
        self.load_time_filter_values()
        
    def set_last_hour_filter(self):
        """Устанавливает фильтр на последний час"""
        current_time = QDateTime.currentDateTime()
        start_time = current_time.addSecs(-3600)
        
        self.start_datetime.setDateTime(start_time)
        self.end_datetime.setDateTime(current_time)
        
        # Применяем фильтр
        self.apply_time_filter()
    
        
    def toggle_auto_refresh(self, state):
        """Включает/выключает автообновление событий"""
        if state == Qt.CheckState.Checked.value:
            # Проверяем, включен ли режим "Все события"
            if self.suricata.config.get('show_all_events', False):
                QMessageBox.warning(
                    self,
                    "Автообновление отключено",
                    "В режиме 'Все события' автообновление отключено для предотвращения задержек."
                )
                self.auto_refresh_check.setChecked(False)
            else:
                self.events_timer.start(10000)
            self.events_timer.start(10000)
            self.load_alerts()  # Загружаем события сразу при включении
        else:
            self.events_timer.stop()
    
        
    def toggle_all_events(self, state):
        """Переключает режим отображения всех событий"""
        self.suricata.config['show_all_events'] = (state == Qt.CheckState.Checked.value)
        self.save_app_settings()
        
        # Если включили режим "Все" и было автообновление - останавливаем
        if self.suricata.config['show_all_events'] and self.events_timer.isActive():
            self.events_timer.stop()
            self.auto_refresh_check.setChecked(False)
            QMessageBox.warning(
                self,
                "Автообновление отключено",
                "В режиме 'Все события' автообновление отключено для предотвращения задержек."
            )
        
        # Если выключили режим "Все" и автообновление было включено - запускаем
        elif not self.suricata.config['show_all_events'] and self.auto_refresh_check.isChecked():
            self.events_timer.start(10000)
        
        self.load_alerts()
        
    def apply_time_filter(self):
        """Применяет фильтр по времени"""
        self.suricata.config['time_filter_enabled'] = True
        self.suricata.config['start_time'] = self.start_datetime.dateTime().toString(Qt.DateFormat.ISODate)
        self.suricata.config['end_time'] = self.end_datetime.dateTime().toString(Qt.DateFormat.ISODate)
        self.save_app_settings()
        self.load_alerts()
    
    def clear_time_filter(self):
        """Сбрасывает фильтр по времени"""
        self.suricata.config['time_filter_enabled'] = False
        self.save_app_settings()
        
        # Устанавливаем значения по умолчанию
        self.set_default_time_filter()
        self.load_alerts()
        
    def load_time_filter_values(self):
        """Загружает сохраненные значения фильтра времени"""
        try:
            # Если есть сохраненные значения - загружаем их
            if self.suricata.config.get('time_filter_enabled', False):
                start_str = self.suricata.config.get('start_time', '')
                end_str = self.suricata.config.get('end_time', '')
                
                if start_str:
                    start_dt = QDateTime.fromString(start_str, Qt.DateFormat.ISODate)
                    if start_dt.isValid():
                        self.start_datetime.setDateTime(start_dt)
                
                if end_str:
                    end_dt = QDateTime.fromString(end_str, Qt.DateFormat.ISODate)
                    if end_dt.isValid():
                        self.end_datetime.setDateTime(end_dt)
        except Exception as e:
            logging.error(f"Ошибка загрузки фильтра времени: {str(e)}")
            # При ошибке устанавливаем значения по умолчанию
            self.set_default_time_filter()
    
    def on_tab_changed(self, index):
        """Обработчик смены вкладки"""
        tab_name = self.tabs.tabText(index)
        
        if tab_name == "События":
            # Обновляем время в фильтре
            self.end_datetime.setDateTime(QDateTime.currentDateTime())
            
            # Если фильтр не активен, обновляем начало
            if not self.suricata.config.get('time_filter_enabled', False):
                self.start_datetime.setDateTime(QDateTime.currentDateTime().addSecs(-3600))
        
        elif tab_name == "Настройки":
            self.load_config()
    
    
    def init_manage_tab(self):
        """Инициализация вкладки управления Suricata"""
        layout = QVBoxLayout()
        
        # Настройка имени службы
        service_layout = QHBoxLayout()
        service_layout.addWidget(QLabel("Имя службы:"))
        
        self.service_edit = QLineEdit(self.suricata.service_name)
        self.service_edit.textChanged.connect(self.update_service_name)
        service_layout.addWidget(self.service_edit)
        
        self.service_cfg_btn = QPushButton("Настроить службу")
        self.service_cfg_btn.clicked.connect(self.configure_service)
        service_layout.addWidget(self.service_cfg_btn)
        
        layout.addLayout(service_layout)
        
        # Статус
        self.status_label = QLabel("Статус: Проверка...")
        self.status_label.setFont(QFont("Arial", 12))
        layout.addWidget(self.status_label)
        
        # Кнопки управления
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Запустить Suricata")
        self.start_btn.clicked.connect(self.start_suricata)
        btn_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Остановить Suricata")
        self.stop_btn.clicked.connect(self.stop_suricata)
        btn_layout.addWidget(self.stop_btn)
        
        self.restart_btn = QPushButton("Перезапустить Suricata")
        self.restart_btn.clicked.connect(self.restart_suricata)
        btn_layout.addWidget(self.restart_btn)
        
        layout.addLayout(btn_layout)
        
        # Информация о службе
        self.service_info = QLabel("")
        layout.addWidget(self.service_info)
        
        # Логи
        self.log_label = QLabel("Журнал приложения:")
        layout.addWidget(self.log_label)
        
        self.log_view = QTableWidget()
        self.log_view.setColumnCount(3)
        self.log_view.setHorizontalHeaderLabels(["Время", "Уровень", "Сообщение"])
        self.log_view.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.log_view)
        
        self.manage_tab.setLayout(layout)
        self.update_log_view()
    
    def show_alert_context_menu(self, pos):
        """Контекстное меню для событий"""
        index = self.alerts_table.indexAt(pos)
        if not index.isValid():
            return
        
        row = index.row()
        event = self.current_events[row]
        local_ips = self.get_local_ips()
        
        menu = QMenu()
        
        # Блокировка источника
        if event['src_ip'] not in local_ips:
            block_src_action = menu.addAction(f"Блокировать источник {event['src_ip']}")
            block_src_action.triggered.connect(lambda: self.block_alert_ip(event['src_ip']))
        
        # Блокировка назначения
        if event['dest_ip'] not in local_ips:
            block_dst_action = menu.addAction(f"Блокировать назначение {event['dest_ip']}")
            block_dst_action.triggered.connect(lambda: self.block_alert_ip(event['dest_ip']))
        
        if menu.actions():
            menu.exec(self.alerts_table.viewport().mapToGlobal(pos))
    
    def configure_service(self):
        """Открывает диалог настройки службы"""
        dialog = ServiceDialog(self.suricata.service_name, self)
        if dialog.exec():
            new_name = dialog.service_edit.text().strip()
            if new_name:
                self.suricata.set_service_name(new_name)
                self.service_edit.setText(new_name)
                self.update_status()
    
    def update_service_name(self):
        """Обновляет имя службы Suricata"""
        service_name = self.service_edit.text().strip()
        if service_name:
            self.suricata.set_service_name(service_name)
            self.update_status()
    
    def update_status(self):
        """Обновляет статус Suricata"""
        try:
            if not self.suricata.service_exists():
                status = "Служба не найдена"
                self.status_label.setText(f"Статус: {status}")
                self.status_bar.showMessage(f"Статус Suricata: {status}")
                self.service_info.setText(f"Служба '{self.suricata.service_name}' не установлена")
                return
                
            status = "Работает" if self.suricata.is_suricata_running() else "Остановлена"
            self.status_label.setText(f"Статус: {status}")
            self.status_bar.showMessage(f"Статус Suricata: {status} (служба: {self.suricata.service_name})")
            
            # Дополнительная информация о службе
            try:
                service_status = win32serviceutil.QueryServiceStatus(self.suricata.service_name)
                state = service_status[1]
                state_name = {
                    win32service.SERVICE_STOPPED: "Остановлена",
                    win32service.SERVICE_START_PENDING: "Запускается",
                    win32service.SERVICE_STOP_PENDING: "Останавливается",
                    win32service.SERVICE_RUNNING: "Работает",
                    win32service.SERVICE_CONTINUE_PENDING: "Возобновляется",
                    win32service.SERVICE_PAUSE_PENDING: "Приостанавливается",
                    win32service.SERVICE_PAUSED: "Приостановлена"
                }.get(state, f"Неизвестно ({state})")
                
                self.service_info.setText(
                    f"Служба: {self.suricata.service_name}\n"
                    f"Статус: {state_name}\n"
                    f"Принимаемые команды: {service_status[2]}"
                )
            except Exception as e:
                self.service_info.setText(f"Ошибка информации о службе: {str(e)}\n{traceback.format_exc()}")
                
        except Exception as e:
            logging.error(f"Error updating status: {str(e)}\n{traceback.format_exc()}")
            self.status_label.setText(f"Статус: Ошибка - {str(e)}")
    
    def update_log_view(self):
        """Обновляет просмотр логов"""
        try:
            self.log_view.setRowCount(0)
            if not os.path.exists('suricata_gui.log'):
                return
                
            # Улучшенная функция tail для чтения последних строк
            def tail(filename, lines=100):
                """Читает последние `lines` строк из файла"""
                try:
                    with open(filename, 'rb') as f:
                        # Переходим в конец файла
                        f.seek(0, os.SEEK_END)
                        end = f.tell()
                        block_size = 4096
                        data = []
                        lines_found = 0
                        
                        # Читаем с конца файла
                        while end > 0 and lines_found < lines:
                            # Считаем назад block_size байт, но не за начало файла
                            if end >= block_size:
                                f.seek(max(end - block_size, 0), os.SEEK_SET)
                                chunk = f.read(block_size)
                            else:
                                f.seek(0, os.SEEK_SET)
                                chunk = f.read(end)
                            
                            end -= block_size
                            # Если ушли в минус, то устанавливаем позицию в 0
                            if end < 0:
                                end = 0
                            
                            # Считаем количество строк в текущем блоке
                            lines_in_chunk = chunk.count(b'\n')
                            lines_found += lines_in_chunk
                            data.append(chunk)
                        
                        # Собираем все блоки в одну строку
                        full_data = b''.join(reversed(data))
                        return full_data.splitlines()[-lines:]
                except Exception as e:
                    logging.error(f"Ошибка чтения логов: {str(e)}")
                    return []
            
            log_lines = tail('suricata_gui.log', 100)
            self.log_view.setRowCount(len(log_lines))
            
            for i, line_bytes in enumerate(log_lines):
                try:
                    line = line_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        line = line_bytes.decode('cp1251')
                    except:
                        line = line_bytes.decode('latin-1', errors='replace')
                
                parts = line.split(' - ', 2)
                if len(parts) < 3:
                    continue
                    
                timestamp = QTableWidgetItem(parts[0])
                level = QTableWidgetItem(parts[1])
                message = QTableWidgetItem(parts[2].strip())
                
                self.log_view.setItem(i, 0, timestamp)
                self.log_view.setItem(i, 1, level)
                self.log_view.setItem(i, 2, message)
                
                # Раскраска по уровню
                if "ERROR" in parts[1]:
                    for col in range(3):
                        self.log_view.item(i, col).setBackground(QColor(255, 200, 200))
                elif "WARNING" in parts[1]:
                    for col in range(3):
                        self.log_view.item(i, col).setBackground(QColor(255, 255, 200))
            
            # Автоматическая подгонка ширины колонок
            self.resize_columns_to_content(self.log_view)
        except Exception as e:
            logging.error(f"Ошибка обновления журнала: {str(e)}\n{traceback.format_exc()}")
    
    def load_rules(self):
        """Загружает список файлов с правилами, проверяя их наличие"""
        self.rule_files_tree.clear()
        rule_files = self.suricata.get_rule_files()
        
        # Проверяем существование каждого файла
        valid_files = []
        missing_files = []
        
        for file in rule_files:
            full_path = os.path.join(self.suricata.rules_dir, file)
            if os.path.exists(full_path):
                valid_files.append(file)
            else:
                missing_files.append(file)
        
        # Если есть отсутствующие файлы, обновляем конфиг
        if missing_files:
            self.suricata.remove_missing_rule_files_from_config(missing_files)
            # Повторно получаем список файлов после обновления
            rule_files = self.suricata.get_rule_files()
        
        for file in rule_files:
            item = QTreeWidgetItem([file])
            item.setData(0, Qt.ItemDataRole.UserRole, file)
            self.rule_files_tree.addTopLevelItem(item)
        
        if rule_files:
            self.rule_files_tree.setCurrentItem(self.rule_files_tree.topLevelItem(0))
    
    
    def on_rule_file_selected(self):
        """Обработчик выбора файла с правилами"""
        self.rules_tree.clear()
        selected = self.rule_files_tree.currentItem()
        if not selected:
            return
            
        filename = selected.data(0, Qt.ItemDataRole.UserRole)
        rules = self.suricata.parse_rules(filename)
        self.current_rules[filename] = rules
        
        for rule in rules:
            item = QTreeWidgetItem([rule['msg'], rule['sid'], 
                                   "Включено" if rule['enabled'] else "Отключено"])
            item.setData(0, Qt.ItemDataRole.UserRole, rule)
            
            # Устанавливаем иконку статуса
            if rule['enabled']:
                item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
                for col in range(3):
                    item.setForeground(col, QColor(0, 0, 0))
            else:
                item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
                for col in range(3):
                    item.setForeground(col, QColor(150, 150, 150))
            
            self.rules_tree.addTopLevelItem(item)
        
        # Автоматическая подгонка ширины колонок
        self.resize_columns_to_content(self.rules_tree)
    
   
    
    def show_rule_details(self, item, column):
        """Показывает детали правила с поддержкой изменений"""
        rule_data = item.data(0, Qt.ItemDataRole.UserRole)
        
        # Передаем manager в диалог
        dialog = RuleDialog(rule_data, self.suricata, self)
        
        if dialog.exec():
            # После закрытия диалога обновляем отображение
            # Определяем текущий файл
            current_file_item = self.rule_files_tree.currentItem()
            if current_file_item:
                self.on_rule_file_selected()
        
   
    
    def import_rules(self):
        """Импортирует файлы с правилами"""
    
        
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Выберите файлы правил",
            "",
            "Правила Suricata (*.rules)"
        )
        
        if not files:
            return
            
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            
            for file in files:
                # Добавляем файлы в конфигурацию Suricata
                filename = os.path.basename(file)
                self.add_rule_to_config(filename)
                
                dest = os.path.join(self.suricata.rules_dir, os.path.basename(file))
                
                if is_admin:
                    shutil.copy(file, dest)
                else:
                    temp_file = os.path.join(tempfile.gettempdir(), os.path.basename(file))
                    shutil.copy(file, temp_file)
                    
                    cmd = f'cmd /c copy /Y "{temp_file}" "{dest}"'
                    
                    process_info = shell.ShellExecuteEx(
                        fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                        lpVerb='runas',
                        lpFile='cmd.exe',
                        lpParameters=cmd,
                        nShow=0
                    )
                    win32event.WaitForSingleObject(process_info['hProcess'], -1)
                    
                    # Исправлено: используем win32api для закрытия дескриптора
                    win32api.CloseHandle(process_info['hProcess'])
                    
                    os.remove(temp_file)
            
            self.load_rules()
            logging.info(f"Импортированные файлы правил: {', '.join(files)}")
            QMessageBox.information(self, "Успех", "Правила успешно импортированы!")
            # После импорта проверяем файлы
            self.check_missing_rule_files()
            self.load_rules()
        except Exception as e:
            logging.error(f"Ошибка импорта правил: {str(e)}\n{traceback.format_exc()}")
            QMessageBox.critical(self, "Ошибка", f"Ошибка импорта правил: {str(e)}")
    
    def add_rule_to_config(self, filename):
        """Добавляет правило в конфигурацию Suricata"""
        try:
            # Загружаем текущий конфиг
            config_text = self.suricata.load_config()
            config = yaml.safe_load(config_text)
            
            # Если раздел rule-files отсутствует, создаем его
            if 'rule-files' not in config:
                config['rule-files'] = []
            
            # Проверяем, есть ли уже это правило
            if filename not in config['rule-files']:
                config['rule-files'].append(filename)
                
                # Преобразуем обратно в YAML
                new_config = yaml.dump(config, default_flow_style=False, sort_keys=False)
                
                # Сохраняем с помощью безопасного метода
                if self.suricata.save_config(new_config):
                    logging.info(f"Файл правил добавлен в конфиг: {filename}")
                else:
                    logging.error(f"Ошибка добавления файла в конфиг: {filename}")
        except Exception as e:
            logging.error(f"Ошибка обновления конфигурации: {str(e)}")
        
        
    def apply_rule_changes(self):
        """Применяет изменения правил"""
        try:
            if self.suricata.restart_suricata():
                logging.info("Изменения правил применены")
                QMessageBox.information(self, "Успех", "Изменения правил успешно применены!")
            else:
                QMessageBox.critical(self, "Ошибка", "Ошибка перезапуска Suricata")
        except Exception as e:
            logging.error(f"Ошибка применения изменений: {str(e)}\n{traceback.format_exc()}")
            QMessageBox.critical(self, "Ошибка", f"Ошибка применения изменений: {str(e)}")

   
    def create_backup(self):
        """Создает резервную копию правил"""
        try:
            backup_path = self.suricata.backup_rules()
            QMessageBox.information(
                self, 
                "Резервная копия создана", 
                f"Резервная копия правил создана в:\n{backup_path}"
            )
        except Exception as e:
            logging.error(f"Ошибка создания резервной копии: {str(e)}\n{traceback.format_exc()}")
            QMessageBox.critical(self, "Ошибка", f"Ошибка создания резервной копии: {str(e)}")
    
    def load_alerts(self):
        """Загружает события в таблицу с поддержкой фильтрации по времени"""
        # если автообновление включено и мы не в режиме "Все"
        if self.auto_refresh_check.isChecked() and not self.suricata.config.get('show_all_events', False):
            # Обновляем конечное время фильтра
            self.end_datetime.setDateTime(QDateTime.currentDateTime())
        
        # Показываем анимацию загрузки
        self.loading_label = QLabel(self)
        self.loading_movie = QMovie("loading.gif")
        self.loading_label.setMovie(self.loading_movie)
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.loading_movie.start()
        
        # Размещаем по центру
        rect = self.alerts_tab.geometry()
        self.loading_label.setGeometry(rect.width()//2 - 50, rect.height()//2 - 50, 100, 100)
        self.loading_label.show()
        QApplication.processEvents()
        try:
            # Показываем статус загрузки
            self.status_bar.showMessage("Загрузка событий...")
            QApplication.processEvents()
            
            # Определяем параметры фильтра
            start_time = None
            end_time = None
            
            if self.suricata.config.get('time_filter_enabled', False):
                try:
                    start_str = self.suricata.config.get('start_time', '')
                    end_str = self.suricata.config.get('end_time', '')
                    
                    if start_str:
                        start_time = datetime.strptime(start_str, '%Y-%m-%dT%H:%M:%S')
                    if end_str:
                        end_time = datetime.strptime(end_str, '%Y-%m-%dT%H:%M:%S')
                except Exception as e:
                    logging.error(f"Ошибка преобразования времени: {str(e)}")
            
            # Определяем режим загрузки
            show_all = self.suricata.config.get('show_all_events', False)
            
            # Загрузка событий
            if show_all:
                events = self.suricata.read_events_with_time_filter(start_time, end_time)
            else:
                try:
                    limit = self.suricata.config['events_limit']
                except KeyError:
                    limit = 1000
                    
                events = self.suricata.read_events(limit)
                
                # Применяем фильтр по времени (если задан)
                if start_time or end_time:
                    filtered_events = []
                    for event in events:
                        try:
                            # Парсим время из события
                            event_time = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
                            
                            if start_time and event_time < start_time:
                                continue
                            if end_time and event_time > end_time:
                                continue
                                
                            filtered_events.append(event)
                        except Exception:
                            # Если не удалось распарсить, оставляем событие
                            filtered_events.append(event)
                    events = filtered_events
            
            # Применяем фильтр по типу события
            filter_type = self.filter_combo.currentIndex()
            if filter_type == 1:  # Alerts Only
                events = [e for e in events if e['event_type'] == 'alert']
            elif filter_type == 2:  # DNS Events
                events = [e for e in events if e['event_type'] == 'dns']
            elif filter_type == 3:  # TLS Events
                events = [e for e in events if e['event_type'] == 'tls']
            
            # Обновляем таблицу
            self.update_events_table(events)
            
            # Обновляем статус
            self.status_bar.showMessage(f"Загружено событий: {len(events)} | Последнее обновление: {datetime.now().strftime('%H:%M:%S')}")
            
        except Exception as e:
            logging.error(f"Ошибка загрузки событий: {str(e)}\n{traceback.format_exc()}")
            self.status_bar.showMessage("Ошибка загрузки событий")
        finally:
            # Скрываем анимацию
            self.loading_label.hide()
            self.loading_movie.stop()
        
    
    def update_events_table(self, events):
        """Обновляет таблицу событий"""
        self.alerts_table.setRowCount(0)
        self.current_events = events
        self.alerts_table.setRowCount(len(events))
        
        for i, event in enumerate(events):
            # Основные поля
            self.alerts_table.setItem(i, 0, QTableWidgetItem(event['timestamp']))
            self.alerts_table.setItem(i, 1, QTableWidgetItem(event['event_type']))
            self.alerts_table.setItem(i, 2, QTableWidgetItem(event.get('signature', 'N/A')))
            self.alerts_table.setItem(i, 3, QTableWidgetItem(event['src_ip']))
            self.alerts_table.setItem(i, 4, QTableWidgetItem(event['dest_ip']))
            self.alerts_table.setItem(i, 5, QTableWidgetItem(event['proto']))
            self.alerts_table.setItem(i, 6, QTableWidgetItem(str(event.get('severity', 0))))
            
            # Колонка действия
            if event.get('blocked', False):
                action_text = 'Блокировка'
            else:
                action = event.get('action', 'unknown')
                action_text = {
                    'alert': 'Логирование',
                    'drop': 'Блокировка',
                    'reject': 'Отклонение',
                    'allowed': 'Разрешено',
                    'unknown': 'Неизвестно'
                }.get(action, action)
            
            # Для наших блокировок гарантируем "Блокировка"
            if 'signature' in event and "GUI Blocked" in event['signature']:
                action_text = 'Блокировка'
            
            self.alerts_table.setItem(i, 7, QTableWidgetItem(action_text))
            
            # Детали в зависимости от типа события
            details = ""
            if event['event_type'] == 'dns':
                details = f"Запрос: {event.get('query', '')}\nОтвет: {event.get('response', '')}"
            elif event['event_type'] == 'tls':
                details = f"SNI: {event.get('sni', '')}\nИздатель: {event.get('issuer', '')}"
            elif event['event_type'] == 'flow':
                details = f"Состояние: {event.get('state', '')}\nПричина: {event.get('reason', '')}"
            else:
                details = event.get('category', '')
                
            self.alerts_table.setItem(i, 8, QTableWidgetItem(details))
            
            # Раскраска
            self.color_event_row(i, event)
        
        # Автоматическая подгонка ширины колонок
        self.resize_columns_to_content(self.alerts_table)
    
    def color_event_row(self, row, event):
        """Раскрашивает строку события в зависимости от типа"""
        if event['event_type'] == 'alert':
            if event.get('severity', 0) >= 3:
                color = QColor(255, 200, 200)  # красный
            elif event.get('severity', 0) >= 2:
                color = QColor(255, 255, 200)  # желтый
            else:
                color = QColor(200, 255, 200)  # зеленый
        elif event['event_type'] == 'dns':
            color = QColor(200, 230, 255)  # голубой
        elif event['event_type'] == 'tls':
            color = QColor(220, 255, 220)  # зеленый
        elif event['event_type'] == 'flow':
            color = QColor(255, 220, 255)  # фиолетовый
        else:
            color = QColor(240, 240, 240)  # серый
        
        for col in range(9):
            self.alerts_table.item(row, col).setBackground(color)
    
    def filter_alerts(self):
        """Фильтрует события по поисковому запросу"""
        search_text = self.search_edit.text().lower()
        if not search_text:
            # Показать все строки
            for i in range(self.alerts_table.rowCount()):
                self.alerts_table.setRowHidden(i, False)
            return
            
        for i in range(self.alerts_table.rowCount()):
            match = False
            for j in range(self.alerts_table.columnCount()):
                item = self.alerts_table.item(i, j)
                if item and search_text in item.text().lower():
                    match = True
                    break
            self.alerts_table.setRowHidden(i, not match)
    
    def get_local_ips(self):
        """Возвращает список локальных IP-адресов системы"""
        local_ips = []
        try:
            hostname = socket.gethostname()
            ips = socket.getaddrinfo(hostname, None)
            for ip in ips:
                ip_addr = ip[4][0]
                if ip_addr not in local_ips and not ip_addr.startswith('127.'):
                    local_ips.append(ip_addr)
        except Exception:
            pass
        return local_ips
    
    def create_readonly_field(self, text, multi_line=False):
        """Создает поле только для чтения"""
        if multi_line:
            text_edit = QTextEdit()
            text_edit.setPlainText(text)
            text_edit.setReadOnly(True)
            return text_edit
        else:
            line_edit = QLineEdit(text)
            line_edit.setReadOnly(True)
            return line_edit
    
    def show_rule_by_sid(self, sid):
        """Находит и показывает правило по SID"""
        if not sid:
            QMessageBox.warning(self, "Ошибка", "SID правила не указан")
            return
            
        found_rule = None
        # Используем новый метод для поиска
        rules = self.suricata.get_all_rules()
        for rule in rules:
            if rule['sid'] == str(sid):
                self.show_rule_details_for_rule(rule)
                found_rule = rule
                return
            if found_rule:
                break
    
        
        if found_rule:
            # Показываем диалог с правилом
            self.show_rule_details_for_rule(found_rule)
        else:
            QMessageBox.information(self, "Правило не найдено", 
                                   f"Правило с SID {sid} не найдено в текущих правилах")
            
    def show_rule_details_for_rule(self, rule):
        """Показывает диалог с деталями правила"""
        # Находим соответствующий файл в дереве
        file_item = None
        for i in range(self.rule_files_tree.topLevelItemCount()):
            item = self.rule_files_tree.topLevelItem(i)
            if item.data(0, Qt.ItemDataRole.UserRole) == rule['file']:
                file_item = item
                break
        
        if file_item:
            # Выбираем файл
            self.rule_files_tree.setCurrentItem(file_item)
            self.on_rule_file_selected()
            
            # Ищем правило в дереве
            for j in range(self.rules_tree.topLevelItemCount()):
                rule_item = self.rules_tree.topLevelItem(j)
                if rule_item.data(0, Qt.ItemDataRole.UserRole)['sid'] == rule['sid']:
                    # Выбираем и открываем правило
                    self.rules_tree.setCurrentItem(rule_item)
                    self.show_rule_details(rule_item, 0)
                    return
        
        # Если не нашли в UI, показываем напрямую
        dialog = RuleDialog(rule, self.suricata, self)
        dialog.exec()
    
    def show_alert_details(self, row, column):
        """Показывает детали события с оптимизированным интерфейсом"""
        event = self.current_events[row]
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Детали события")
        dialog.setGeometry(300, 300, 700, 700)  # Немного увеличили высоту
        
        # Основной макет
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        
        content_widget = QWidget()
        content_layout = QVBoxLayout()
        content_layout.setSpacing(10)  # Уменьшенное расстояние между элементами
        content_layout.setContentsMargins(15, 15, 15, 15)
        
        # === Основная информация ===
        form_layout = QFormLayout()
        
        # Функция для создания полей только для чтения
        def create_readonly_field(text, multi_line=False):
            if multi_line:
                text_edit = QTextEdit()
                text_edit.setPlainText(text)
                text_edit.setReadOnly(True)
                return text_edit
            else:
                line_edit = QLineEdit(text)
                line_edit.setReadOnly(True)
                return line_edit
        
        # Основные поля события
        form_layout.addRow("Время:", create_readonly_field(event['timestamp']))
        form_layout.addRow("Тип события:", create_readonly_field(event['event_type']))
        form_layout.addRow("Источник:", create_readonly_field(event['src_ip']))
        form_layout.addRow("Назначение:", create_readonly_field(event['dest_ip']))
        form_layout.addRow("Протокол:", create_readonly_field(event['proto']))
        form_layout.addRow("Важность:", create_readonly_field(str(event.get('severity', 0))))
        
        # Действие - всегда отображаем реальное действие
        if event.get('blocked', False):
            action_text = "Блокировка"
        else:
            action = event.get('action', 'unknown')
            action_text = {
                'alert': 'Логирование',
                'drop': 'Блокировка',
                'reject': 'Отклонение',
                'allowed': 'Разрешено',
                'unknown': 'Неизвестно'
            }.get(action, action)
        
        form_layout.addRow("Действие:", create_readonly_field(action_text))

        # Группа для основной информации
        main_info_group = QGroupBox("Основная информация")
        main_info_group.setLayout(form_layout)
        content_layout.addWidget(main_info_group)
        
        # === Сырые данные ===
        raw_group = QGroupBox("Сырые данные")
        raw_layout = QVBoxLayout()
        
        raw_data = QTextEdit()
        raw_data.setFixedHeight(160)  # Фиксированная высота 160px
        raw_data.setReadOnly(True)
        raw_data.setFont(QFont("Consolas", 10))
        
        try:
            # Пытаемся отформатировать JSON
            parsed = json.loads(event.get('raw', '{}'))
            formatted = json.dumps(parsed, indent=4, ensure_ascii=False)
            raw_data.setPlainText(formatted)
            # Включаем подсветку
            highlighter = JsonHighlighter(raw_data.document())
        except:
            # Если не удалось разобрать как JSON, показываем как есть
            raw_data.setPlainText(event.get('raw', 'N/A'))
        
        raw_layout.addWidget(QLabel("Сырые данные:"))
        raw_layout.addWidget(raw_data)
        
        copy_raw_btn = QPushButton("Копировать сырые данные")
        copy_raw_btn.clicked.connect(lambda: QApplication.clipboard().setText(event.get('raw', '')))
        raw_layout.addWidget(copy_raw_btn)
        
        raw_group.setLayout(raw_layout)
        content_layout.addWidget(raw_group)
        
        # === Информация о правиле (только для алертов) ===
        if event.get('event_type') == 'alert':
            rule_info = self.create_rule_info_widget(event, dialog)
            content_layout.addWidget(rule_info)
        
        # === Действия ===
        actions_group = QGroupBox("Действия")
        actions_layout = QVBoxLayout()
        
        # Блок блокировки IP
        # Определяем локальные IP
        local_ips = self.get_local_ips()
        
        # Определяем, какой IP внешний
        src_is_local = event['src_ip'] in local_ips
        dst_is_local = event['dest_ip'] in local_ips
        
        # Создаем кнопки блокировки
        ip_actions_layout = QHBoxLayout()
        
        # Кнопка блокировки источника
        if not src_is_local and event['src_ip'] != 'N/A':
            block_src_btn = QPushButton(f"Блокировать источник: {event['src_ip']}")
            block_src_btn.clicked.connect(lambda: self.block_alert_ip(event['src_ip'], dialog))
            ip_actions_layout.addWidget(block_src_btn)
        
        # Кнопка блокировки назначения
        if not dst_is_local and event['dest_ip'] != 'N/A':
            block_dst_btn = QPushButton(f"Блокировать назначение: {event['dest_ip']}")
            block_dst_btn.clicked.connect(lambda: self.block_alert_ip(event['dest_ip'], dialog))
            ip_actions_layout.addWidget(block_dst_btn)
        
        # Если оба IP локальные (внутренняя сеть), предлагаем оба варианта
        if src_is_local and dst_is_local:
            block_src_btn = QPushButton(f"Блокировать источник: {event['src_ip']}")
            block_src_btn.clicked.connect(lambda: self.block_alert_ip(event['src_ip'], dialog))
            ip_actions_layout.addWidget(block_src_btn)
            
            block_dst_btn = QPushButton(f"Блокировать назначение: {event['dest_ip']}")
            block_dst_btn.clicked.connect(lambda: self.block_alert_ip(event['dest_ip'], dialog))
            ip_actions_layout.addWidget(block_dst_btn)
        
        # Добавляем в layout
        if ip_actions_layout.count() > 0:
            actions_layout.addLayout(ip_actions_layout)
        
        # Кнопка закрытия
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(dialog.accept)
        actions_layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)
        
        actions_group.setLayout(actions_layout)
        content_layout.addWidget(actions_group)
        
        # Устанавливаем стили для компактности
        main_info_group.setStyleSheet("QGroupBox { padding: 5px; }")
        raw_group.setStyleSheet("QGroupBox { padding: 5px; }")
        actions_group.setStyleSheet("QGroupBox { padding: 5px; }")
        
        content_widget.setLayout(content_layout)
        scroll_area.setWidget(content_widget)
        
        dialog_layout = QVBoxLayout()
        dialog_layout.addWidget(scroll_area)
        dialog.setLayout(dialog_layout)
        
        dialog.exec()
    
        
    def create_rule_info_widget(self, event, dialog):
        """Создает компактный виджет с информацией о правиле"""
        rule_group = QGroupBox("Информация о правиле")
        rule_layout = QGridLayout()  # Используем сетку для компактного размещения
        rule_layout.setVerticalSpacing(5)  # Уменьшаем вертикальные отступы
        
        # Заголовки и значения в сетке
        rule_layout.addWidget(QLabel("Файл:"), 0, 0)
        file_label = QLabel(event.get('rule_file', 'N/A'))
        file_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        rule_layout.addWidget(file_label, 0, 1)
        
        rule_layout.addWidget(QLabel("SID:"), 1, 0)
        sid_label = QLabel(str(event.get('sid', 'N/A')))
        sid_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        rule_layout.addWidget(sid_label, 1, 1)
        
        rule_layout.addWidget(QLabel("Название:"), 2, 0, 1, 2)  # Занимает 2 колонки
        name_label = QLabel(event.get('signature', 'N/A'))
        name_label.setWordWrap(True)
        name_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        rule_layout.addWidget(name_label, 3, 0, 1, 2)
        
        # Кнопки в отдельной строке
        btn_layout = QHBoxLayout()
        
        if event.get('sid'):
            view_btn = QPushButton("Просмотреть")
            view_btn.clicked.connect(lambda: self.show_rule_by_sid(event.get('sid')))
            btn_layout.addWidget(view_btn)
            
            disable_btn = QPushButton("Отключить")
            disable_btn.clicked.connect(lambda: self.disable_rule_by_sid(event.get('sid'), dialog))
            btn_layout.addWidget(disable_btn)
        
        rule_layout.addLayout(btn_layout, 4, 0, 1, 2)
        
        rule_group.setLayout(rule_layout)
        return rule_group
      
    def load_events(self):
        """Загружает события из Suricata"""
        events = self.suricata.get_events()
        
        # Добавляем информацию о действии правила
        for event in events:
            if event['event_type'] == 'alert' and 'sid' in event:
                # Проверяем статус правила в Suricata
                rule_status = self.suricata.get_rule_status(event['sid'])
                event['action'] = rule_status['action']
                event['enabled'] = rule_status['enabled']
        
        self.current_events = events
        self.update_event_table()


    def disable_rule_by_sid(self, sid, dialog):
        """Отключает правило по SID из диалога события"""
        try:
            if sid is None:
                QMessageBox.warning(dialog, "Ошибка", "SID правила не указан")
                return
                
            if self.suricata.toggle_rule_by_sid(sid, False):
                # Обновляем событие, если оно отображается
                for event in self.current_events:
                    if event.get('sid') == sid:
                        event['action'] = 'disabled'
                        event['enabled'] = False
                        break
                
                QMessageBox.information(
                    dialog, 
                    "Правило отключено", 
                    f"Правило SID {sid} отключено.\nНе забудьте перезапустить Suricata для применения изменений."
                )
            else:
                QMessageBox.critical(
                    dialog, 
                    "Ошибка", 
                    f"Не удалось отключить правило SID {sid}"
                )
        except Exception as e:
            logging.error(f"Ошибка отключения правила: {str(e)}\n{traceback.format_exc()}")
            QMessageBox.critical(
                dialog, 
                "Критическая ошибка", 
                f"Ошибка отключения правила: {str(e)}"
            )
    
    def apply_rule_action(self, sid, action, dialog):
        """Применяет выбранное действие к правилу"""
        try:
            success = False
            message = ""
            
            if action == "disable":
                success = self.suricata.toggle_rule_by_sid(sid, False)
                message = "Правило отключено"
            elif action in ["alert", "drop", "reject"]:
                # Сначала включаем правило (если было отключено)
                self.suricata.toggle_rule_by_sid(sid, True)
                success = self.suricata.change_rule_action(sid, action)
                message = f"Действие правила изменено на '{action}'"
            
            if success:
                # Обновляем статус в текущих событиях
                for evt in self.current_events:
                    if evt.get('sid') == sid:
                        if action == "disable":
                            evt['action'] = 'disabled'
                            evt['enabled'] = False
                        else:
                            evt['action'] = action
                        break
                
                QMessageBox.information(
                    dialog,
                    "Успех",
                    f"{message} для SID {sid}\n\nНе забудьте перезапустить Suricata для применения изменений."
                )
            else:
                QMessageBox.critical(
                    dialog,
                    "Ошибка",
                    f"Не удалось применить действие к правилу SID {sid}"
                )
        except Exception as e:
            logging.error(f"Ошибка применения действия: {str(e)}\n{traceback.format_exc()}")
            QMessageBox.critical(
                dialog,
                "Ошибка",
                f"Ошибка применения действия: {str(e)}"
            )
    
    def block_alert_ip(self, ip, dialog):
        """Блокирует указанный IP"""
        try:
            if self.suricata.add_drop_rule(ip):
                # Обновляем все события, связанные с этим IP
                for event in self.current_events:
                    if event['src_ip'] == ip or event['dest_ip'] == ip:
                        event['blocked'] = True
                        event['action'] = 'drop'
                        event['signature'] = f"GUI: Blocked IP {ip}"
                
                # Безопасный перезапуск службы
                if self.suricata.restart_suricata():
                    QMessageBox.information(
                        dialog, 
                        "IP заблокирован", 
                        f"IP {ip} заблокирован и Suricata перезапущен"
                    )
                    logging.info(f"Заблокирован IP: {ip}")
                    dialog.accept()
                else:
                    QMessageBox.warning(
                        dialog, 
                        "Ошибка", 
                        f"IP {ip} добавлен в правила, но не удалось перезапустить Suricata"
                    )
            else:
                QMessageBox.critical(
                    dialog, 
                    "Ошибка", 
                    f"Не удалось добавить правило блокировки для IP {ip}"
                )
        except Exception as e:
            logging.error(f"Ошибка блокировки IP: {str(e)}\n{traceback.format_exc()}")
            QMessageBox.critical(
                dialog, 
                "Ошибка", 
                f"Ошибка блокировки IP: {str(e)}"
            )
    

    
    def start_suricata(self):
        """Запускает Suricata"""
        if not self.suricata.service_exists():
            self.show_service_warning()
            return
            
        try:
            if self.suricata.start_suricata():
                logging.info("Suricata запущена")
                QMessageBox.information(self, "Успех", "Suricata успешно запущена")
                self.update_status()
            else:
                QMessageBox.critical(self, "Ошибка", "Ошибка запуска Suricata")
        except Exception as e:
            logging.error(f"Ошибка запуска Suricata: {str(e)}\n{traceback.format_exc()}")
            QMessageBox.critical(self, "Ошибка", f"Ошибка запуска Suricata: {str(e)}")
    
    def stop_suricata(self):
        """Останавливает Suricata"""
        if not self.suricata.service_exists():
            self.show_service_warning()
            return
            
        try:
            if self.suricata.stop_suricata():
                logging.info("Suricata остановлена")
                QMessageBox.information(self, "Успех", "Suricata успешно остановлена")
                self.update_status()
            else:
                QMessageBox.critical(self, "Ошибка", "Ошибка остановки Suricata")
        except Exception as e:
            logging.error(f"Ошибка остановки Suricata: {str(e)}\n{traceback.format_exc()}")
            QMessageBox.critical(self, "Ошибка", f"Ошибка остановки Suricata: {str(e)}")
    
    def restart_suricata(self):
        """Перезапускает Suricata"""
        if not self.suricata.service_exists():
            self.show_service_warning()
            return
            
        try:
            if self.suricata.restart_suricata():
                logging.info("Suricata перезапущена")
                QMessageBox.information(self, "Успех", "Suricata успешно перезапущена")
                self.update_status()
            else:
                QMessageBox.critical(self, "Ошибка", "Ошибка перезапуска Suricata")
        except Exception as e:
            logging.error(f"Ошибка перезапуска Suricata: {str(e)}\n{traceback.format_exc()}")
            QMessageBox.critical(self, "Ошибка", f"Ошибка перезапуска Suricata: {str(e)}")
            

class RuleSources:
    """Класс для управления источниками правил"""
    
    CONFIG_FILE = "rule_sources.ini"
    
    def __init__(self):
        self.sources = []
        self.load_sources()
    
    def load_sources(self):
        """Загружает список источников из конфигурационного файла"""
        self.sources = []
        config = configparser.ConfigParser()
        
        # Проверяем существование файла конфигурации
        if os.path.exists(self.CONFIG_FILE):
            try:
                # Читаем существующий конфиг
                config.read(self.CONFIG_FILE)
                
                # Проверяем наличие секции Sources
                if 'Sources' in config:
                    # Проходим по всем источникам в секции
                    for name in config['Sources']:
                        url = config['Sources'][name]
                        self.sources.append({
                            'name': name,
                            'url': url
                        })
                    logging.info(f"Загружено {len(self.sources)} источников правил")
                else:
                    logging.warning("Конфигурационный файл не содержит секции 'Sources'")
                    
            except Exception as e:
                logging.error(f"Ошибка чтения конфигурации источников: {str(e)}")
                # Создаем резервную копию поврежденного файла
                backup_file = f"{self.CONFIG_FILE}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy(self.CONFIG_FILE, backup_file)
                logging.error(f"Создана резервная копия конфигурации: {backup_file}")
                
                # Создаем новый файл с базовыми источниками
                self._create_default_config()
                self.load_sources()  # Рекурсивно загружаем заново
                
        else:
            # Файл не существует - создаем конфиг по умолчанию
            self._create_default_config()
            self.load_sources()  # Рекурсивно загружаем заново
    
    def _create_default_config(self):
        """Создает конфигурационный файл с источниками по умолчанию"""
        config = configparser.ConfigParser()
        config['Sources'] = {
            'Abuse.ch JA3': 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.tar.gz',
            'ET Open Rules': 'https://rules.emergingthreats.net/open/suricata-6.0.0/emerging.rules.tar.gz',
            'SSLBL IP Blacklist': 'https://sslbl.abuse.ch/blacklist/sslblacklist.rules'
        }
        
        try:
            with open(self.CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
            logging.info(f"Создан новый конфигурационный файл с источниками по умолчанию")
        except Exception as e:
            logging.error(f"Ошибка создания конфигурационного файла: {str(e)}")
    
    def save_sources(self):
        """Сохраняет источники в конфигурационный файл"""
        config = configparser.ConfigParser()
        config['Sources'] = {}
        
        for source in self.sources:
            config['Sources'][source['name']] = source['url']
        
        try:
            with open(self.CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
            return True
        except Exception as e:
            logging.error(f"Ошибка сохранения источников: {str(e)}")
            return False
    
    def add_source(self, name, url):
        """Добавляет новый источник"""
        self.sources.append({'name': name, 'url': url})
        return self.save_sources()
    
    def remove_source(self, index):
        """Удаляет источник по индексу"""
        if 0 <= index < len(self.sources):
            del self.sources[index]
            return self.save_sources()
        return False
    
    def download_and_extract(self, url, dest_dir):
        """Скачивает и распаковывает правила из URL, возвращает список путей к файлам"""
        # Создаем временный файл
        temp_file = tempfile.mktemp()
        extracted_files = []
        
        try:
            # Скачиваем файл с таймаутом
            try:
                with urllib.request.urlopen(url, timeout=30) as response, open(temp_file, 'wb') as out_file:
                    shutil.copyfileobj(response, out_file)
            except Exception as e:
                raise ConnectionError(f"Ошибка скачивания: {str(e)}")
            
            # Определяем тип файла по расширению
            if url.endswith('.tar.gz') or url.endswith('.tgz'):
                # Распаковываем tar.gz
                with tarfile.open(temp_file, "r:gz") as tar:
                    self._extract_rules(tar, dest_dir)
                    
            elif url.endswith('.zip'):
                # Распаковываем zip
                with zipfile.ZipFile(temp_file, 'r') as zip_ref:
                    self._extract_rules(zip_ref, dest_dir)
                    
            elif url.endswith('.rules'):
                # Просто копируем файл правил
                dest_path = os.path.join(dest_dir, os.path.basename(url))
                shutil.copy(temp_file, dest_path)
                
            else:
                raise ValueError(f"Неподдерживаемый формат файла: {url}")
            
            # Собираем список всех файлов .rules в целевой директории
            for root, _, files in os.walk(dest_dir):
                for file in files:
                    if file.endswith('.rules'):
                        extracted_files.append(os.path.join(root, file))
            
            return extracted_files
        except Exception as e:
            logging.error(f"Ошибка обработки {url}: {str(e)}")
            return []
        finally:
            # Всегда удаляем временный файл
            if os.path.exists(temp_file):
                os.remove(temp_file)
    
    def _extract_rules(self, archive, dest_dir):
        """Извлекает файлы правил из архива"""
        # Получаем список всех файлов в архиве
        if isinstance(archive, tarfile.TarFile):
            members = archive.getmembers()
        else:  # zipfile.ZipFile
            members = archive.namelist()

        # Фильтруем только файлы .rules
        rule_files = []
        for m in members:
            # Для tar-архивов
            if isinstance(archive, tarfile.TarFile):
                if m.isfile() and m.name.endswith('.rules'):
                    rule_files.append(m)
            # Для zip-архивов
            else:
                if not m.endswith('/') and m.endswith('.rules'):  # проверка, что это файл, а не папка
                    rule_files.append(m)
        
        # Извлекаем каждый файл правил
        for member in rule_files:
            try:
                # Для tar
                if isinstance(archive, tarfile.TarFile):
                    # Извлекаем в буфер
                    extracted = archive.extractfile(member)
                    if extracted:
                        # Сохраняем в целевой директории
                        dest_path = os.path.join(dest_dir, os.path.basename(member.name))
                        with open(dest_path, 'wb') as f:
                            f.write(extracted.read())
                
                # Для zip
                elif isinstance(archive, zipfile.ZipFile):
                    # Извлекаем только имя файла без пути
                    filename = os.path.basename(member)
                    dest_path = os.path.join(dest_dir, filename)
                    
                    # Извлекаем содержимое файла
                    with archive.open(member) as source_file:
                        with open(dest_path, 'wb') as target_file:
                            shutil.copyfileobj(source_file, target_file)
                        
            except Exception as e:
                logging.error(f"Ошибка извлечения файла {member}: {str(e)}")