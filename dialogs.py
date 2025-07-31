# -*- coding: utf-8 -*-
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QCheckBox, QHBoxLayout,
    QTextEdit, QDialogButtonBox, QLabel, QPushButton, QMessageBox,
    QComboBox
)
from PyQt6.QtCore import Qt
import win32service
import win32serviceutil
import pywintypes
import re
import logging

class RuleDialog(QDialog):
    """Диалог для просмотра и редактирования правила"""
    
    def __init__(self, rule_data, manager, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Детали правила")
        self.setGeometry(300, 300, 600, 400)
        
        # Проверяем наличие обязательных полей
        if 'raw' not in rule_data:
            rule_data['raw'] = "No rule content"
        if 'sid' not in rule_data:
            rule_data['sid'] = "N/A"
        if 'msg' not in rule_data:
            rule_data['msg'] = "No message"
        if 'file' not in rule_data:
            rule_data['file'] = "Unknown file"
        if 'enabled' not in rule_data:
            rule_data['enabled'] = True
            
        self.rule_data = rule_data
        self.manager = manager  # Добавляем ссылку на SuricataManager
        
        # Проверяем, есть ли файл в конфиге
        self.check_file_in_config(rule_data['file'])
        
        layout = QVBoxLayout()
        
        # Форма с деталями правила
        form_layout = QFormLayout()
        
        self.enabled_check = QCheckBox("Активно")
        self.enabled_check.setChecked(rule_data['enabled'])
        form_layout.addRow("Статус:", self.enabled_check)
        
        self.sid_edit = QLineEdit(rule_data['sid'])
        self.sid_edit.setReadOnly(True)
        form_layout.addRow("SID:", self.sid_edit)
        
        self.msg_edit = QLineEdit(rule_data['msg'])
        form_layout.addRow("Сообщение:", self.msg_edit)
        
        self.file_edit = QLineEdit(rule_data['file'])
        self.file_edit.setReadOnly(True)
        form_layout.addRow("Файл:", self.file_edit)
        
        # Добавляем выбор действия
        action_layout = QHBoxLayout()
        action_layout.addWidget(QLabel("Действие:"))
        
        self.action_combo = QComboBox()
        self.action_combo.addItems(["alert", "drop", "reject", "pass"])
        current_action = self.get_current_action(rule_data['raw'], rule_data['enabled'])
        self.action_combo.setCurrentText(current_action)
        
        action_layout.addWidget(self.action_combo)
        action_layout.addStretch()  # добавляем растяжку справа
        
        form_layout.addRow(action_layout)
        
        # Поле для редактирования сырого правила
        self.rule_edit = QTextEdit()
        self.rule_edit.setPlainText(rule_data['raw'])
        form_layout.addRow("Правило:", self.rule_edit)
        
        layout.addLayout(form_layout)
        
        # Кнопки
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Apply |
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        button_box.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(self.apply_changes)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
    
    def get_current_action(self, raw_rule, enabled):
        """Извлекает текущее действие из правила"""
        if not enabled:
            raw_rule = raw_rule.lstrip('#').strip()
        
        parts = raw_rule.split()
        if parts:
            return parts[0]
        return "alert"
    
    def check_file_in_config(self, filename):
        """Проверяет и добавляет файл в конфиг при необходимости"""
        if not self.manager.is_rule_file_in_config(filename):
            reply = QMessageBox.question(
                self,
                "Файл не в конфигурации",
                f"Файл правил '{filename}' не включен в конфигурацию Suricata.\n"
                "Хотите добавить его сейчас?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                if self.manager.add_rule_file_to_config(filename):
                    QMessageBox.information(
                        self, 
                        "Успех", 
                        f"Файл '{filename}' добавлен в конфигурацию.\n"
                        "Не забудьте перезапустить Suricata для применения изменений."
                    )
                else:
                    QMessageBox.warning(
                        self, 
                        "Ошибка", 
                        f"Не удалось добавить файл '{filename}' в конфигурацию."
                    )
    
    def apply_changes(self):
        """Применяет изменения без закрытия диалога"""
        try:
            # Получаем новые данные
            new_enabled = self.enabled_check.isChecked()
            new_raw = self.rule_edit.toPlainText().strip()
            new_action = self.action_combo.currentText()
    
            # Создаем копию оригинальных данных для сравнения
            updated_data = self.rule_data.copy()
    
            # Определяем, что изменилось
            enabled_changed = new_enabled != self.rule_data['enabled']
            raw_changed = new_raw != self.rule_data['raw']
    
            # Если изменилось действие
            current_action = self.get_current_action(self.rule_data['raw'], self.rule_data['enabled'])
            action_changed = new_action != current_action
    
            if not enabled_changed and not raw_changed and not action_changed:
                return  # Ничего не изменилось
    
            # Если изменилось только действие
            if action_changed and not raw_changed and not enabled_changed:
                # Создаем копию правила с новым действием
                parts = self.rule_data['raw'].split()
                if parts:
                    parts[0] = new_action
                    new_raw = ' '.join(parts)
    
                    # Создаем обновленные данные
                    updated_data = self.rule_data.copy()
                    updated_data['raw'] = new_raw
    
                    # Заменяем правило
                    if self.manager.replace_rule(self.rule_data, updated_data):
                        self.rule_data.update(updated_data)
                        QMessageBox.information(self, "Успех", "Действие правила успешно изменено!")
                    else:
                        QMessageBox.warning(self, "Ошибка", "Не удалось изменить действие правила")
                return
    
            # Если изменился только статус
            if enabled_changed and not raw_changed and not action_changed:
                # Используем метод toggle_rule
                if self.manager.toggle_rule(self.rule_data, new_enabled):
                    self.rule_data['enabled'] = new_enabled
                    QMessageBox.information(self, "Успех", "Статус правила обновлен!")
                else:
                    QMessageBox.warning(self, "Ошибка", "Не удалось изменить статус правила")
                return
    
            # Если изменилось само правило
            # Обновляем данные
            updated_data['raw'] = new_raw
            updated_data['enabled'] = new_enabled
    
            # Извлекаем новую информацию
            working_line = new_raw
            if not new_enabled:
                working_line = working_line.lstrip('#').lstrip()
    
            # Обновляем SID и сообщение
            sid_match = re.search(r'sid:(\d+);', working_line)
            updated_data['sid'] = sid_match.group(1) if sid_match and sid_match.group(1) else "N/A"
    
            msg_match = re.search(r'msg:"([^"]+)"', working_line)
            updated_data['msg'] = msg_match.group(1) if msg_match and msg_match.group(1) else "No message"
    
            # Заменяем правило целиком
            if self.manager.replace_rule(self.rule_data, updated_data):
                # Обновляем локальные данные
                self.rule_data.update(updated_data)
    
                # Обновляем UI
                self.sid_edit.setText(updated_data['sid'])
                self.msg_edit.setText(updated_data['msg'])
    
                QMessageBox.information(self, "Успех", "Правило полностью обновлено!")
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось обновить правило")
    
        except Exception as e:
            logging.error(f"Ошибка применения изменений: {str(e)}")
            QMessageBox.critical(self, "Ошибка", f"Ошибка применения изменений: {str(e)}")
    
    def accept(self):
        """Применяет изменения и закрывает диалог"""
        self.apply_changes()
        super().accept()


class ServiceDialog(QDialog):
    """Диалог для настройки службы Suricata"""
    
    def __init__(self, service_name, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройка службы Suricata")
        self.setGeometry(300, 300, 400, 200)
        
        layout = QVBoxLayout()
        
        self.service_edit = QLineEdit(service_name)
        self.status_label = QLabel("Статус: Проверка...")
        
        self.test_btn = QPushButton("Проверить службу")
        self.test_btn.clicked.connect(self.test_service)
        
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        
        layout.addWidget(QLabel("Имя службы:"))
        layout.addWidget(self.service_edit)
        layout.addWidget(self.status_label)
        layout.addWidget(self.test_btn)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
        self.test_service()
    
    def test_service(self):
        """Проверяет доступность службы"""
        service_name = self.service_edit.text().strip()
        if not service_name:
            self.status_label.setText("Статус: Введите имя службы")
            return
            
        try:
            # Проверка существования службы
            try:
                status = win32serviceutil.QueryServiceStatus(service_name)
                status_text = "ЗАПУЩЕНА" if status[1] == win32service.SERVICE_RUNNING else "ОСТАНОВЛЕНА"
                self.status_label.setText(f"Статус: Служба существует ({status_text})")
            except pywintypes.error as e:
                if e.winerror == 1060:  # Служба не найдена
                    self.status_label.setText("Статус: Служба не найдена")
                else:
                    self.status_label.setText(f"Статус: Ошибка - {e.strerror}")
        except Exception as e:
            self.status_label.setText(f"Статус: Ошибка - {str(e)}")