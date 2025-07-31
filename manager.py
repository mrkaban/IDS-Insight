# -*- coding: utf-8 -*-
import os
import json
import logging
import shutil
import re
import traceback
from datetime import datetime
import win32service
import win32serviceutil
import pywintypes
import yaml
import ctypes
import tempfile
from win32com.shell import shell, shellcon
import win32event
import win32api
import configparser


class SuricataManager:
    """Класс для управления Suricata и правилами"""
    
    def __init__(self):
        self.config = {
            'suricata_path': r"C:\Program Files\Suricata\suricata.exe",
            'config_file': r"C:\Program Files\Suricata\suricata.yaml",
            'rules_dir': r"C:\Program Files\Suricata\rules",
            'eve_log': r"C:\Program Files\Suricata\log\eve.json",
            'interfaces': [r"\Device\NPF_{C25E28E9-E46B-46DB-8B45-1A0C30816B68}"],
            'drop_rules': "gui_drop.rules",
            'backup_dir': r"C:\Program Files\Suricata\backups",
            'service_name': "SuricataService",
            'events_limit': 1000,
            'show_all_events': False,
            'time_filter_enabled': False,
            'start_time': '',
            'end_time': '',
            'auto_refresh': True  # Добавляем новый параметр со значением по умолчанию
        }
        self.rule_index = {}  # sid -> (filename, rule_data)
        self.index_built = False
        self.service_name = self.config['service_name']
        self.rules_dir = self.config['rules_dir']
        self.eve_log = self.config['eve_log']
        self.drop_rules = os.path.join(self.config['rules_dir'], self.config['drop_rules'])
        self.backup_dir = self.config['backup_dir']
        self.config_file = self.config['config_file']
        self.ensure_directories()
        self.ensure_drop_rules_in_config()
        self.events_cache = {}
        self.cache_time = None
        self.cache_duration = 60  # секунд
        # Загружаем пользовательские настройки
        self.load_app_config()
    
    def build_rule_index(self):
        """Строит индекс правил для быстрого поиска"""
        self.rule_index = {}
        rule_files = self.get_rule_files()
        
        for filename in rule_files:
            filepath = os.path.join(self.rules_dir, filename)
            try:
                rules = self.parse_rules(filename)
                for rule in rules:
                    if rule['sid'] != "N/A":
                        self.rule_index[rule['sid']] = (filename, rule)
            except Exception as e:
                logging.error(f"Ошибка индексации файла {filename}: {str(e)}")
        
        self.index_built = True
        logging.info(f"Построен индекс {len(self.rule_index)} правил")
    
    def find_rule_by_sid(self, sid):
        """Находит правило по SID используя индекс"""
        sid_str = str(sid)
        if not self.index_built:
            self.build_rule_index()
        return self.rule_index.get(sid_str, (None, None))
    
    
    def check_rule_files_existence(self):
        """
        Проверяет существование всех файлов правил из конфигурации.
        Возвращает список отсутствующих файлов.
        """
        missing_files = []
        try:
            config_text = self.load_config()
            config = yaml.safe_load(config_text) or {}
            rule_files = config.get('rule-files', [])
            
            for file in rule_files:
                full_path = os.path.join(self.rules_dir, file)
                if not os.path.exists(full_path):
                    missing_files.append(file)
                    
        except Exception as e:
            logging.error(f"Ошибка проверки файлов правил: {str(e)}")
            
        return missing_files
    
    def remove_missing_rule_files_from_config(self, missing_files):
        """
        Удаляет отсутствующие файлы из конфигурации.
        Возвращает True, если изменения были внесены.
        """
        try:
            config_text = self.load_config()
            config = yaml.safe_load(config_text) or {}
            
            if 'rule-files' in config:
                # Удаляем отсутствующие файлы
                original_count = len(config['rule-files'])
                config['rule-files'] = [f for f in config['rule-files'] if f not in missing_files]
                
                if len(config['rule-files']) != original_count:
                    # Сохраняем обновленную конфигурацию
                    new_config = yaml.dump(config, default_flow_style=False, sort_keys=False)
                    return self.save_config(new_config)
                    
        except Exception as e:
            logging.error(f"Ошибка удаления отсутствующих файлов из конфига: {str(e)}")
        
        return False
    
        
    def ensure_drop_rules_in_config(self):
        """Убеждается, что drop-правила включены в конфигурацию"""
        try:
            config_text = self.load_config()
            config = yaml.safe_load(config_text) or {}
            
            drop_filename = os.path.basename(self.drop_rules)
            rule_files = config.get('rule-files', [])
            
            if drop_filename not in rule_files:
                rule_files.append(drop_filename)
                config['rule-files'] = rule_files
                new_config = yaml.dump(config, default_flow_style=False, sort_keys=False)
                self.save_config(new_config)
                logging.info(f"Добавлен файл drop-правил в конфигурацию: {drop_filename}")
                
                # Создаем файл, если не существует
                if not os.path.exists(self.drop_rules):
                    with open(self.drop_rules, 'w') as f:
                        f.write("# GUI Drop Rules\n")
        except Exception as e:
            logging.error(f"Ошибка проверки drop-правил: {str(e)}")
            
    def add_rule_file_to_config(self, filename):
        """Добавляет файл правил в конфигурацию"""
        # Проверяем существование файла перед добавлением
        full_path = os.path.join(self.rules_dir, filename)
        if not os.path.exists(full_path):
            logging.warning(f"Файл {filename} не существует, не добавляем в конфиг")
            return False
        
        try:
            config_text = self.load_config()
            config = yaml.safe_load(config_text) or {}
            
            if 'rule-files' not in config:
                config['rule-files'] = []
            
            rule_files = config['rule-files']
            base_name = os.path.basename(filename)
            
            if base_name not in rule_files:
                rule_files.append(base_name)
                new_config = yaml.dump(config, default_flow_style=False, sort_keys=False)
                if self.save_config(new_config):
                    logging.info(f"Файл правил добавлен в конфигурацию: {base_name}")
                    return True
            return False
        except Exception as e:
            logging.error(f"Ошибка добавления файла в конфигурацию: {str(e)}")
            return False
        
    def is_rule_file_in_config(self, filename):
        """Проверяет, есть ли файл правил в конфигурации"""
        try:
            config_text = self.load_config()
            config = yaml.safe_load(config_text) or {}
            rule_files = config.get('rule-files', [])
            base_name = os.path.basename(filename)
            return base_name in rule_files
        except Exception as e:
            logging.error(f"Ошибка проверки наличия файла в конфиге: {str(e)}")
            return False
    
    def load_app_config(self):
        """Загружает настройки приложения из файла"""
        config_file = "suricata_gui.ini"
        if os.path.exists(config_file):
            try:
                config = configparser.ConfigParser()
                config.read(config_file)
                if 'Settings' in config:
                    settings = config['Settings']
                    
                    # Используем правильный метод для получения значений
                    self.config['suricata_path'] = settings.get('suricata_path', self.config['suricata_path'])
                    self.config['rules_dir'] = settings.get('rules_dir', self.config['rules_dir'])
                    self.config['eve_log'] = settings.get('eve_log', self.config['eve_log'])
                    self.config['backup_dir'] = settings.get('backup_dir', self.config['backup_dir'])
                    
                    # Для числовых значений
                    try:
                        self.config['events_limit'] = int(settings.get('events_limit', self.config['events_limit']))
                    except ValueError:
                        pass
                    
                    # Для булевых значений
                    self.config['show_all_events'] = settings.get('show_all_events', str(self.config['show_all_events'])).lower() == 'true'
                    self.config['time_filter_enabled'] = settings.get('time_filter_enabled', str(self.config['time_filter_enabled'])).lower() == 'true'
                    self.config['auto_refresh'] = settings.get('auto_refresh', str(self.config['auto_refresh'])).lower() == 'true'
                    
                    # Для строковых значений времени
                    self.config['start_time'] = settings.get('start_time', self.config['start_time'])
                    self.config['end_time'] = settings.get('end_time', self.config['end_time'])
                    
            except Exception as e:
                logging.error(f"Ошибка загрузки настроек приложения: {str(e)}")
                
    def get_all_rules(self):
        """Возвращает все правила из всех файлов"""
        all_rules = []
        rule_files = self.get_rule_files()
        for filename in rule_files:
            all_rules.extend(self.parse_rules(filename))
        return all_rules
        
       
    def safe_write_file(self, filepath, content):
        """Безопасно записывает содержимое в файл с обработкой прав доступа"""
        # Проверяем, что файл является правилом или конфигом
        if not (filepath.endswith('.rules') or filepath.endswith('.yaml')):
            logging.error(f"Попытка записи в неразрешенный файл: {filepath}")
            return False
        
        # Проверяем, что файл находится в разрешенной директории
        allowed_dirs = [self.rules_dir, self.backup_dir, os.path.dirname(self.config_file)]
        if not any(filepath.startswith(d) for d in allowed_dirs):
            logging.error(f"Попытка записи в неразрешенную директорию: {filepath}")
            return False
        try:
            # Проверяем права администратора
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            
            if is_admin:
                # Прямая запись если есть права
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                return True
            else:
                # Создаем временный файл
                temp_file = tempfile.mktemp()
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Команда для копирования с перезаписью
                cmd = f'cmd /c copy /Y "{temp_file}" "{filepath}"'
                
                # Запускаем с правами администратора
                process_info = shell.ShellExecuteEx(
                    fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                    lpVerb='runas',
                    lpFile='cmd.exe',
                    lpParameters=cmd,
                    nShow=0
                )
                win32event.WaitForSingleObject(process_info['hProcess'], -1)
                win32api.CloseHandle(process_info['hProcess'])
                
                # Удаляем временный файл
                os.remove(temp_file)
                return True
                
        except Exception as e:
            logging.error(f"Ошибка записи файла {filepath}: {str(e)}")
            return False
        
    def safe_service_action(self, action):
        """Безопасное выполнение действий со службой с обработкой прав"""
        # МЕТОД РАБОТАЕТ, ИСПРАВИШЬ, В ГОЛОВУ ДАМ!
        try:
            # Проверяем права администратора
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            
            if is_admin:
                # Выполняем действие напрямую
                if action == "start":
                    return win32serviceutil.StartService(self.service_name)
                elif action == "stop":
                    return win32serviceutil.StopService(self.service_name)
                elif action == "restart":
                    return win32serviceutil.RestartService(self.service_name)
            else:
                # Создаем командный файл
                bat_content = f"@echo off\n"
                if action == "restart":
                    bat_content += f"net stop \"{self.service_name}\"\n"
                    bat_content += f"net start \"{self.service_name}\"\n"
                else:
                    bat_content += f"net {action} \"{self.service_name}\"\n"
                bat_content += "exit 0\n"
                
                # Создаем временный bat-файл
                temp_dir = tempfile.mkdtemp()
                bat_path = os.path.join(temp_dir, f"service_{action}.bat")
                with open(bat_path, 'w') as f:
                    f.write(bat_content)
                
                # Запускаем с правами администратора
                process_info = shell.ShellExecuteEx(
                    fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                    lpVerb='runas',
                    lpFile=bat_path,
                    nShow=0
                )
                win32event.WaitForSingleObject(process_info['hProcess'], -1)
                win32api.CloseHandle(process_info['hProcess'])
                
                # Удаляем временную директорию
                shutil.rmtree(temp_dir, ignore_errors=True)
                return True
                
        except Exception as e:
            logging.error(f"Ошибка выполнения действия {action} для службы: {str(e)}")
            return False
    
    def replace_rule(self, old_rule, new_rule):
        """Полностью заменяет правило в файле"""
        try:
            filepath = os.path.join(self.rules_dir, old_rule['file'])
            
            # Читаем текущее содержимое файла
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.readlines()
            
            new_content = []
            rule_replaced = False
            
            for line in content:
                stripped_line = line.rstrip()
                
                # Ищем правило по SID и оригинальному содержанию
                if old_rule['sid'] in line and stripped_line == old_rule['raw']:
                    # Заменяем на новое правило
                    new_content.append(new_rule['raw'] + '\n')
                    rule_replaced = True
                else:
                    new_content.append(line)
            
            if not rule_replaced:
                logging.warning(f"Rule with SID {old_rule['sid']} not found in {filepath}")
                return False
            
            # Записываем измененное содержимое через безопасный метод
            return self.safe_write_file(filepath, ''.join(new_content))
            
        except Exception as e:
            logging.error(f"Error replacing rule: {traceback.format_exc()}")
            return False
        
    def set_service_name(self, name):
        """Устанавливает имя службы Suricata"""
        self.config['service_name'] = name
        self.service_name = name
        
    def ensure_directories(self):
        """Создает необходимые директории"""
        try:
            os.makedirs(self.rules_dir, exist_ok=True)
            os.makedirs(self.backup_dir, exist_ok=True)
            
            # Создаем файл для drop-правил если не существует
            drop_rules_path = os.path.join(self.rules_dir, self.config['drop_rules'])
            if not os.path.exists(drop_rules_path):
                open(drop_rules_path, 'w').close()
        except Exception as e:
            logging.error(f"Ошибка создания директорий: {str(e)}")
        
    def backup_rules(self):
        """Создает резервную копию правил"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(self.backup_dir, f"rules_backup_{timestamp}")
        shutil.copytree(self.rules_dir, backup_path)
        logging.info(f"Created rules backup: {backup_path}")
        return backup_path
        
    def get_rule_files(self):
        """Возвращает список файлов с правилами"""
        return [f for f in os.listdir(self.rules_dir) if f.endswith('.rules')]
    
    def parse_rules(self, filename):
        """Парсит правила из файла, включая отключенные"""
        rules = []
        filepath = os.path.join(self.rules_dir, filename)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    original_line = line.rstrip()  # Сохраняем оригинальную строку
                    
                    # Определяем состояние правила
                    enabled = True
                    working_line = original_line
                    
                    # Проверяем, отключено ли правило
                    if working_line.startswith('#'):
                        enabled = False
                        # Убираем символ комментария только для анализа
                        working_line = working_line.lstrip('#').lstrip()
                    
                    # Пропускаем пустые строки
                    if not working_line.strip():
                        continue
                    
                    # Извлечение SID
                    sid_match = re.search(r'sid:(\d+);', working_line)
                    sid = sid_match.group(1) if sid_match else "N/A"
                    
                    # Извлечение сообщения
                    msg_match = re.search(r'msg:"([^"]+)"', working_line)
                    msg = msg_match.group(1) if msg_match else "No message"
                    
                    rules.append({
                        'raw': original_line,  # Сохраняем оригинальную строку
                        'enabled': enabled,
                        'sid': sid,
                        'msg': msg,
                        'file': filename
                    })
        except Exception as e:
            logging.error(f"Error parsing rules: {traceback.format_exc()}")
            logging.error(f"File: {filepath}, Error: {str(e)}")
        
        return rules
    
   
    
    def toggle_rule(self, rule_data, enable):
        """Включает/выключает правило по SID"""
        try:
            filepath = os.path.join(self.rules_dir, rule_data['file'])
            sid = rule_data['sid']
            
            # Читаем текущее содержимое файла
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.readlines()
            
            new_content = []
            rule_found = False
            
            for line in content:
                if f"sid:{sid};" in line:
                    rule_found = True
                    if enable:
                        # Убираем комментирование
                        if line.strip().startswith('#'):
                            line = line.lstrip('#').lstrip()
                    else:
                        # Добавляем комментирование
                        if not line.strip().startswith('#'):
                            line = '# ' + line
                new_content.append(line)
            
            if not rule_found:
                logging.warning(f"Rule with SID {sid} not found in {filepath}")
                return False
            
            # Записываем измененное содержимое через безопасный метод
            return self.safe_write_file(filepath, ''.join(new_content))
            
        except Exception as e:
            logging.error(f"Error toggling rule: {traceback.format_exc()}")
            return False
    
   
    
    def toggle_rule_by_sid(self, sid, enable):
        """Включает/выключает правило по SID (ищет во всех файлах)"""
        rule_files = self.get_rule_files()
        
        for filename in rule_files:
            rules = self.parse_rules(filename)
            for rule in rules:
                if rule['sid'] == sid:
                    return self.toggle_rule(rule, enable)
        
        return False
    
    
    
    def change_rule_action(self, sid, new_action):
        """Изменяет действие правила (alert, drop, reject) по SID"""
        rule_files = self.get_rule_files()
        
        for filename in rule_files:
            filepath = os.path.join(self.rules_dir, filename)
            try:
                # Читаем текущее содержимое файла
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.readlines()
                
                new_content = []
                rule_found = False
                
                for line in content:
                    # Ищем правило по SID
                    if f"sid:{sid};" in line and not line.strip().startswith('#'):
                        rule_found = True
                        # Заменяем действие (первое слово в правиле)
                        parts = line.split()
                        if len(parts) > 0:
                            parts[0] = new_action
                            line = ' '.join(parts) + '\n'
                    new_content.append(line)
                
                if rule_found:
                    # Используем безопасную запись
                    return self.safe_write_file(filepath, ''.join(new_content))
            except Exception as e:
                logging.error(f"Error changing rule action: {traceback.format_exc()}")
                logging.error(f"File: {filepath}, Error: {str(e)}")
        
        return False


    
    def toggle_rule_file(self, filename, enable):
        """Включает/выключает весь файл правил"""
        filepath = os.path.join(self.rules_dir, filename)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Включаем/выключаем все правила
            if enable:
                content = re.sub(r'^#\s*', '', content, flags=re.MULTILINE)
            else:
                content = re.sub(r'^([^#\n])', r'# \1', content, flags=re.MULTILINE)
            
            # Безопасная запись
            return self.safe_write_file(filepath, content)
            
        except Exception as e:
            logging.error(f"Error toggling rule file: {traceback.format_exc()}")
            return False
    
    
    
    def add_drop_rule(self, ip):
        """Добавляет правило для блокировки IP с явным указанием действия"""
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            logging.error(f"Invalid IP address: {ip}")
            return False
            
        try:
            # Читаем текущее содержимое файла
            current_content = ""
            if os.path.exists(self.drop_rules):
                with open(self.drop_rules, 'r', encoding='utf-8') as f:
                    current_content = f.read()
            
            # Генерируем уникальный SID
            sid = self.get_next_drop_sid()
            
            # Исправленная строка с сигнатурой - без двоеточия
            new_rule = (
                f'drop ip {ip} any -> any any '
                f'(msg:"GUI Blocked IP {ip}"; '  # Убрано двоеточие после GUI
                f'flow:to_client; '
                f'flowint:gui_blocked_ip,set,1; '
                f'flowint:gui_action_drop,set,1; '
                f'sid:{sid}; '
                f'rev:1;)\n'
            )
            
            new_content = current_content + new_rule
            
            # Безопасная запись
            self.safe_write_file(self.drop_rules, new_content)
            
            self.update_eve_config_for_drops()
            
            self.ensure_action_in_eve_config()
            return True
                
        except Exception as e:
            logging.error(f"Error adding drop rule: {traceback.format_exc()}")
            return False
        
    def update_eve_config_for_drops(self):
        """Обновляет конфиг Eve для правильного отображения блокировок"""
        try:
            config_text = self.load_config()
            config = yaml.safe_load(config_text) or {}
            
            # Добавляем кастомный вывод для блокировок
            if 'eve-log' not in config:
                config['eve-log'] = {}
                
            eve_log = config['eve-log']
            
            if 'types' not in eve_log:
                eve_log['types'] = ['alert']
            
            # Добавляем кастомные поля
            if 'custom' not in eve_log:
                eve_log['custom'] = []
                
            custom_fields = [
                {
                    'name': 'blocked',
                    'value': 'flowint.gui_blocked_ip'
                },
                {
                    'name': 'real_action',
                    'value': 'alert.action'
                }
            ]
            
            # Добавляем только отсутствующие поля
            for new_field in custom_fields:
                if not any(f['name'] == new_field['name'] for f in eve_log['custom']):
                    eve_log['custom'].append(new_field)
            
            # Сохраняем конфиг
            new_config = yaml.dump(config, default_flow_style=False, sort_keys=False)
            self.save_config(new_config)
            self.restart_suricata()
            
        except Exception as e:
            logging.error(f"Ошибка обновления конфигурации Eve: {str(e)}")
    
    
    def ensure_action_in_eve_config(self):
        """Убеждается, что в конфигурации включено логирование действия"""
        try:
            config_text = self.load_config()
            config = yaml.safe_load(config_text) or {}
            
            # Находим раздел eve-log
            if 'eve-log' not in config:
                config['eve-log'] = {}
                
            eve_log = config['eve-log']
            
            # Включаем логирование метаданных
            if 'types' not in eve_log:
                eve_log['types'] = ['alert']
            
            # Добавляем metadata в logged_fields
            if 'alert' not in eve_log:
                eve_log['alert'] = {}
                
            alert_config = eve_log['alert']
            
            if 'metadata' not in alert_config.get('logged_fields', {}):
                if 'logged_fields' not in alert_config:
                    alert_config['logged_fields'] = {}
                
                alert_config['logged_fields']['metadata'] = ['action']
                
                # Сохраняем обновленную конфигурацию
                new_config = yaml.dump(config, default_flow_style=False, sort_keys=False)
                self.save_config(new_config)
                logging.info("Добавлено логирование поля action в метаданных")
                
                # Перезапускаем Suricata для применения изменений
                self.restart_suricata()
        except Exception as e:
            logging.error(f"Ошибка обновления конфигурации: {str(e)}")
    
    
    def get_next_drop_sid(self):
        """Генерирует следующий SID для правил блокировки"""
        try:
            if os.path.exists(self.drop_rules):
                with open(self.drop_rules, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Ищем максимальный SID
                    sids = re.findall(r'sid:(\d+);', content)
                    if sids:
                        max_sid = max(int(sid) for sid in sids)
                        return max_sid + 1
            return 1000000  # Начальное значение
        except Exception:
            return 1000000
    
    def read_events_with_time_filter(self, start_time=None, end_time=None):
        """Читает события с кэшированием"""
        cache_key = f"{start_time}_{end_time}"
        
        # Проверяем актуальность кэша
        if (cache_key in self.events_cache and 
            self.cache_time and 
            (datetime.now() - self.cache_time).total_seconds() < self.cache_duration):
            return self.events_cache[cache_key]
        
        # Читаем и кэшируем события
        events = self._read_events_with_time_filter(start_time, end_time)
        self.events_cache[cache_key] = events
        self.cache_time = datetime.now()
        
        return events
    
    def _read_events_with_time_filter(self, start_time=None, end_time=None):
        """Читает все события с фильтрацией по времени (оптимизированная версия)"""
        events = []
        try:
            if not os.path.exists(self.eve_log):
                return events
            
            # Используем более эффективное чтение с буферизацией
            buffer = []
            buffer_size = 1000  # Размер буфера
            
            with open(self.eve_log, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or not line.startswith('{'):
                        continue
                    
                    buffer.append(line)
                    
                    # Обрабатываем буфер при заполнении
                    if len(buffer) >= buffer_size:
                        self.process_buffer(buffer, events, start_time, end_time)
                        buffer = []
                
                # Обрабатываем остаток
                if buffer:
                    self.process_buffer(buffer, events, start_time, end_time)
        
        except Exception as e:
            logging.error(f"Ошибка чтения событий: {str(e)}\n{traceback.format_exc()}")
        
        # Сортируем по времени (новые сверху)
        try:
            events.sort(key=lambda x: datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S'), reverse=True)
        except:
            # Резервная сортировка по строке
            events.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return events
    
    def process_buffer(self, buffer, events, start_time, end_time):
        """Обрабатывает буфер строк и добавляет события в список"""
        for line in buffer:
            try:
                event = json.loads(line)
                
                # Парсим время события
                ts_str = event.get('timestamp', '')
                if not ts_str:
                    continue
                    
                # Пытаемся преобразовать в datetime
                event_time = None
                try:
                    # Формат: "2023-01-01T12:34:56.789+0300"
                    if '.' in ts_str:
                        dt_str = ts_str.split('.')[0]
                        event_time = datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S')
                    # Формат без миллисекунд: "2023-01-01T12:34:56+0300"
                    elif 'T' in ts_str:
                        dt_str = ts_str.split('+')[0]
                        event_time = datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S')
                except:
                    pass
                
                # Применяем фильтр по времени
                if event_time:
                    if start_time and event_time < start_time:
                        continue
                    if end_time and event_time > end_time:
                        continue
                elif start_time or end_time:
                    # Если не удалось распарсить время, пропускаем при активном фильтре
                    continue
                
                # Используем стандартную функцию обработки события
                processed_event = self.process_event(event, line)
                if processed_event:
                    events.append(processed_event)
                    
            except Exception as e:
                logging.debug(f"Ошибка обработки строки: {str(e)}\nСтрока: {line}")
        
    def process_event(self, event, raw_line):
        """Обрабатывает одно событие (общая функция для всех методов чтения)"""
        # Проверяем наличие обязательного поля
        if 'event_type' not in event:
            return None
    
        event_type = event.get('event_type', 'unknown')
        
        # Определение действия
        action = "unknown"
        
        # 1. Кастомные flowint для блокировок
        if 'flowint' in event and ('gui_action_drop' in event['flowint'] or 'gui_blocked_ip' in event['flowint']):
            action = 'drop'
        
        # 2. Для алертов проверяем сигнатуру
        if action == "unknown" and event_type == 'alert':
            alert_obj = event.get('alert', {})
            signature = alert_obj.get('signature', '')
            
            if "Blocked IP" in signature or "GUI Blocked" in signature:
                action = 'drop'
            elif 'action' in alert_obj:
                action = alert_obj['action']
            elif signature:
                parts = signature.split()
                if parts:
                    first_word = parts[0].lower()
                    if first_word in ['alert', 'drop', 'reject', 'pass']:
                        action = first_word
        
        # 3. Действие из корневого уровня
        if action == "unknown" and 'action' in event:
            action = event['action']
        
        # 4. Для flow событий
        if action == "unknown" and event_type == 'flow':
            flow_flags = event.get('flow', {}).get('flags', [])
            if 'drop' in flow_flags:
                action = 'drop'
            elif 'reject' in flow_flags:
                action = 'reject'
            else:
                action = 'allow'
        
        # 5. Универсальное правило
        if action == "unknown" and event_type not in ["alert", "flow"]:
            action = "logged"
        
        # 6. Действие по умолчанию для алертов
        if action == "unknown" and event_type == 'alert':
            action = "alert"
        
        # Обработка временной метки
        ts = event.get('timestamp')
        timestamp_str = "N/A"
        
        if isinstance(ts, (int, float)):
            timestamp_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(ts, str):
            try:
                if '.' in ts and 'T' in ts:
                    dt_str = ts.split('.')[0].replace('T', ' ')
                    timestamp_str = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                elif 'T' in ts:
                    dt_str = ts.split('+')[0].replace('T', ' ')
                    timestamp_str = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                else:
                    timestamp_str = ts
            except Exception:
                timestamp_str = ts
        else:
            timestamp_str = str(ts)
        
        # Базовые поля
        base_event = {
            'timestamp': timestamp_str,
            'event_type': event_type,
            'src_ip': event.get('src_ip', 'N/A'),
            'dest_ip': event.get('dest_ip', 'N/A'),
            'proto': event.get('proto', 'N/A'),
            'action': action,
            'raw': raw_line  # Используем переданную raw_line
        }
            
        # Дополнительные поля для алертов
        if event_type == 'alert':
            base_event['signature'] = event['alert'].get('signature', 'N/A')
            base_event['category'] = event['alert'].get('category', 'N/A')
            
            # Обработка severity
            severity = event['alert'].get('severity', 0)
            if isinstance(severity, str):
                try:
                    base_event['severity'] = int(severity)
                except ValueError:
                    base_event['severity'] = 0
            else:
                base_event['severity'] = severity or 0
            
            # Обработка signature_id
            sid = event['alert'].get('signature_id', 0)
            if isinstance(sid, str):
                try:
                    base_event['sid'] = int(sid)
                except ValueError:
                    base_event['sid'] = 0
            else:
                base_event['sid'] = sid or 0
                
            # Уточнение действия для алертов
            if 'metadata' in event and 'action' in event['metadata']:
                base_event['action'] = event['metadata']['action']
            elif 'flowint' in event and 'gui_blocked_ip' in event['flowint']:
                base_event['action'] = "drop"
            elif 'action' in alert_obj:
                base_event['action'] = alert_obj['action']
            elif 'signature' in alert_obj:
                signature = alert_obj['signature']
                if "block" in signature.lower() or "drop" in signature.lower() or "GUI Blocked IP" in signature:
                    base_event['action'] = "drop"
                elif "reject" in signature.lower():
                    base_event['action'] = "reject"
                else:
                    base_event['action'] = "alert"
            
            # Гарантируем drop для кастомных правил
            if 'metadata' in event and 'action' in event['metadata'] and event['metadata']['action'] == 'drop':
                base_event['action'] = "drop"
            if 'flowint' in event and 'gui_action_drop' in event['flowint']:
                base_event['action'] = "drop"
            if 'signature' in alert_obj and "GUI Blocked IP" in alert_obj['signature']:
                if 'flowint' in event and 'gui_blocked_ip' in event['flowint']:
                    base_event['action'] = "drop"
                else:
                    base_event['action'] = "drop"
        
        # Обработка DNS
        elif event_type == 'dns':
            base_event['signature'] = 'DNS Query'
            base_event['category'] = 'DNS'
            base_event['severity'] = 1
            base_event['query'] = event.get('dns', {}).get('rrname', 'N/A')
            
            answers = []
            for ans in event.get('dns', {}).get('answers', []):
                if 'rdata' in ans:
                    answers.append(ans['rdata'])
                elif 'aaaa' in ans:
                    answers.append(ans['aaaa'])
            base_event['response'] = ', '.join(answers) if answers else "N/A"
        
        # Обработка TLS
        elif event_type == 'tls':
            base_event['signature'] = 'TLS Handshake'
            base_event['category'] = 'TLS'
            base_event['severity'] = 1
            base_event['sni'] = event.get('tls', {}).get('sni', 'N/A')
            base_event['issuer'] = event.get('tls', {}).get('issuerdn', 'N/A')
        
        # Обработка BitTorrent
        elif event_type == 'bittorrent_dht':
            base_event['signature'] = 'BitTorrent DHT'
            base_event['category'] = 'P2P'
            base_event['severity'] = 2
            base_event['dht_type'] = event.get('bittorrent_dht', {}).get('type', 'unknown')
            base_event['nodes'] = str(len(event.get('bittorrent_dht', {}).get('nodes', [])))
        
        # Обработка flow
        elif event_type == 'flow':
            base_event['signature'] = 'Network Flow'
            base_event['category'] = 'Flow'
            base_event['severity'] = 0
            base_event['state'] = event.get('flow', {}).get('state', 'N/A')
            base_event['reason'] = event.get('flow', {}).get('reason', 'N/A')
        
        # Другие типы событий
        else:
            base_event['signature'] = event_type
            base_event['category'] = 'Other'
            base_event['severity'] = 1
        
        # Поиск файла правила для алертов
        if event_type == 'alert':
            sid = base_event.get('sid', 0)
            if sid:
                rule_file, _ = self.find_rule_by_sid(sid)
                base_event['rule_file'] = rule_file or "Unknown"
            else:
                base_event['rule_file'] = "N/A"
        else:
            base_event['rule_file'] = "N/A"
            
        # Помечаем блокировки
        if action == 'drop':
            base_event['blocked'] = True
            base_event['severity'] = max(base_event.get('severity', 0), 3)
            if 'signature' not in base_event:
                base_event['signature'] = f"GUI Blocked IP {base_event['src_ip']}"
    
        return base_event
    

    def parse_event_time(self, ts_str):
        """Парсит строку времени в datetime"""
        if not ts_str:
            return None
        
        try:
            # Формат: "2023-01-01T12:34:56.789+0300"
            if '.' in ts_str:
                return datetime.strptime(ts_str.split('.')[0], '%Y-%m-%dT%H:%M:%S')
            # Формат без миллисекунд: "2023-01-01T12:34:56+0300"
            elif 'T' in ts_str:
                return datetime.strptime(ts_str.split('+')[0], '%Y-%m-%dT%H:%M:%S')
            # Числовой формат (timestamp)
            else:
                try:
                    return datetime.fromtimestamp(float(ts_str))
                except ValueError:
                    return None
        except:
            return None

   
    def read_events(self, limit=None):
        """Читает события из eve.json с обработкой разных форматов времени"""
        events = []
        
        if limit is None:
            limit = self.config['events_limit']  # Используем значение из конфига
        
        try:
            if not os.path.exists(self.eve_log):
                logging.error(f"Файл журнала не найден: {self.eve_log}")
                return events
                
            # Улучшенная функция tail для больших файлов
            def tail(filename, lines=limit):
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
                    logging.error(f"Ошибка чтения файла: {str(e)}")
                    return []
            
            log_lines = tail(self.eve_log, limit)
            
            for line_bytes in log_lines:
                try:
                    # Пытаемся декодить как UTF-8
                    line = line_bytes.decode('utf-8').strip()
                except UnicodeDecodeError:
                    try:
                        # Пробуем другие кодировки
                        line = line_bytes.decode('cp1251').strip()
                    except:
                        try:
                            line = line_bytes.decode('latin-1').strip()
                        except:
                            # Если ничего не помогает, пропускаем строку
                            continue
                
                # Пропускаем пустые строки
                if not line:
                    continue
                
                # Пропускаем строки, которые не являются JSON-объектами
                if not line.startswith('{'):
                    continue
                
                try:
                    # Пытаемся разобрать JSON
                    event = json.loads(line)
                    
                    # Проверяем, что это событие содержит обязательные поля
                    if 'event_type' not in event:
                        continue
                        
                    event_type = event.get('event_type', 'unknown')
                    
                    
                    # ОПРЕДЕЛЕНИЕ ДЕЙСТВИЯ - ИСПРАВЛЕННАЯ ВЕРСИЯ
                    action = "unknown"
                    
                    # 1. Проверяем наши кастомные flowint для блокировок
                    if 'flowint' in event and ('gui_action_drop' in event['flowint'] or 'gui_blocked_ip' in event['flowint']):
                        action = 'drop'
                    
                    # 2. Для алертов проверяем сигнатуру
                    if action == "unknown" and event_type == 'alert':
                        alert_obj = event.get('alert', {})
                        signature = alert_obj.get('signature', '')
                        
                        # Для наших правил блокировки гарантируем "drop"
                        if "Blocked IP" in signature or "GUI Blocked" in signature:
                            action = 'drop'
                        
                        # Проверяем явное поле action в alert
                        elif 'action' in alert_obj:
                            action = alert_obj['action']
                        
                        # Определяем по первому слову в сигнатуре
                        elif signature:
                            parts = signature.split()
                            if parts:
                                first_word = parts[0].lower()
                                if first_word in ['alert', 'drop', 'reject', 'pass']:
                                    action = first_word
                    
                    # 3. Пробуем получить действие из корневого уровня
                    if action == "unknown" and 'action' in event:
                        action = event['action']
                    
                    # 4. Для flow событий определяем действие по flags
                    if action == "unknown" and event_type == 'flow':
                        flow_flags = event.get('flow', {}).get('flags', [])
                        if 'drop' in flow_flags:
                            action = 'drop'
                        elif 'reject' in flow_flags:
                            action = 'reject'
                        else:
                            action = 'allow'
                    
                    # 5. Универсальное правило для не-alert/flow
                    if action == "unknown" and event_type not in ["alert", "flow"]:
                        action = "logged"
                    
                    # 6. Если для алерта действие не определено - ставим "alert"
                    if action == "unknown" and event_type == 'alert':
                        action = "alert"
                    
                    
                    # Универсальная обработка временной метки
                    ts = event.get('timestamp')
                    timestamp_str = "N/A"
                    
                    if isinstance(ts, (int, float)):
                        # Числовой формат (Unix timestamp)
                        timestamp_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                    elif isinstance(ts, str):
                        # Попробуем разные строковые форматы
                        try:
                            # Формат ISO с миллисекундами: "2023-01-01T12:34:56.789+0300"
                            if '.' in ts and 'T' in ts:
                                dt_str = ts.split('.')[0].replace('T', ' ')
                                timestamp_str = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                            # Формат без миллисекунд: "2023-01-01T12:34:56+0300"
                            elif 'T' in ts:
                                dt_str = ts.split('+')[0].replace('T', ' ')
                                timestamp_str = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                            # Другие возможные форматы
                            else:
                                timestamp_str = ts  # Оставляем оригинальное значение
                        except Exception as ts_e:
                            timestamp_str = ts
                    else:
                        timestamp_str = str(ts)
                    
                    # Базовые поля для всех событий
                    base_event = {
                        'timestamp': timestamp_str,
                        'event_type': event_type,
                        'src_ip': event.get('src_ip', 'N/A'),
                        'dest_ip': event.get('dest_ip', 'N/A'),
                        'proto': event.get('proto', 'N/A'),
                        'action': action,  # Используем вычисленное действие
                        'raw': line
                    }
                        
                    # Дополнительные поля для алертов
                    if event_type == 'alert':
                        base_event['signature'] = event['alert'].get('signature', 'N/A')
                        base_event['category'] = event['alert'].get('category', 'N/A')
                        
                        # Обработка severity (может быть строкой или числом)
                        severity = event['alert'].get('severity', 0)
                        if isinstance(severity, str):
                            try:
                                base_event['severity'] = int(severity)
                            except ValueError:
                                base_event['severity'] = 0
                        else:
                            base_event['severity'] = severity or 0
                        
                        # Обработка signature_id
                        sid = event['alert'].get('signature_id', 0)
                        if isinstance(sid, str):
                            try:
                                base_event['sid'] = int(sid)
                            except ValueError:
                                base_event['sid'] = 0
                        else:
                            base_event['sid'] = sid or 0
                            
                        # 1. Проверяем явное указание действия в metadata
                        if 'metadata' in event and 'action' in event['metadata']:
                            base_event['action'] = event['metadata']['action']
                        
                        # 2. Проверяем наше кастомное поле flowint
                        elif 'flowint' in event and 'gui_blocked_ip' in event['flowint']:
                            base_event['action'] = "drop"
                        
                        # 3. Проверяем поле alert.action
                        elif 'action' in alert_obj:
                            base_event['action'] = alert_obj['action']
                        
                        # 4. Определяем по сигнатуре
                        elif 'signature' in alert_obj:
                            signature = alert_obj['signature']
                            if "block" in signature.lower() or "drop" in signature.lower() or "GUI Blocked IP" in signature:
                                base_event['action'] = "drop"
                            elif "reject" in signature.lower():
                                base_event['action'] = "reject"
                            else:
                                base_event['action'] = "alert"
                        
                        # 5. Для наших кастомных правил гарантируем "drop"
                        if 'metadata' in event and 'action' in event['metadata'] and event['metadata']['action'] == 'drop':
                            base_event['action'] = "drop"
                        
                        if 'flowint' in event and 'gui_action_drop' in event['flowint']:
                            base_event['action'] = "drop"
                            
                        # Для наших кастомных блокировок
                        if 'signature' in alert_obj and "GUI Blocked IP" in alert_obj['signature']:
                            # Проверяем наличие flowvar
                            if 'flowint' in event and 'gui_blocked_ip' in event['flowint']:
                                base_event['action'] = "drop"
                            else:
                                # Если flowvar отсутствует, но сигнатура наша - считаем блокировкой
                                base_event['action'] = "drop"
                        
                    # Обработка DNS событий
                    elif event_type == 'dns':
                        base_event['signature'] = 'DNS Query'
                        base_event['category'] = 'DNS'
                        base_event['severity'] = 1
                        base_event['query'] = event.get('dns', {}).get('rrname', 'N/A')
                        
                        # Формирование списка ответов
                        answers = []
                        for ans in event.get('dns', {}).get('answers', []):
                            if 'rdata' in ans:
                                answers.append(ans['rdata'])
                            elif 'aaaa' in ans:
                                answers.append(ans['aaaa'])
                        
                        base_event['response'] = ', '.join(answers) if answers else "N/A"
                    # Обработка TLS событий
                    elif event_type == 'tls':
                        base_event['signature'] = 'TLS Handshake'
                        base_event['category'] = 'TLS'
                        base_event['severity'] = 1
                        base_event['sni'] = event.get('tls', {}).get('sni', 'N/A')
                        base_event['issuer'] = event.get('tls', {}).get('issuerdn', 'N/A')
                    # Обработка BitTorrent DHT событий
                    elif event_type == 'bittorrent_dht':
                        base_event['signature'] = 'BitTorrent DHT'
                        base_event['category'] = 'P2P'
                        base_event['severity'] = 2
                        base_event['dht_type'] = event.get('bittorrent_dht', {}).get('type', 'unknown')
                        base_event['nodes'] = str(len(event.get('bittorrent_dht', {}).get('nodes', [])))
                    # Обработка flow событий
                    elif event_type == 'flow':
                        base_event['signature'] = 'Network Flow'
                        base_event['category'] = 'Flow'
                        base_event['severity'] = 0
                        base_event['state'] = event.get('flow', {}).get('state', 'N/A')
                        base_event['reason'] = event.get('flow', {}).get('reason', 'N/A')
                    # Другие типы событий
                    else:
                        base_event['signature'] = event_type
                        base_event['category'] = 'Other'
                        base_event['severity'] = 1
                    
                    # Добавляем информацию о правиле для алертов
                    if 'event_type' in base_event and base_event['event_type'] == 'alert':
                        sid = base_event.get('sid', 0)
                        if sid:
                            # Пытаемся найти файл правила по SID
                            rule_file, _ = self.find_rule_by_sid(sid)
                            base_event['rule_file'] = rule_file if rule_file else "Unknown"
                            # rule_file = self.find_rule_file_by_sid(sid)
                            # base_event['rule_file'] = rule_file
                        else:
                            base_event['rule_file'] = "N/A"
                    else:
                        base_event['rule_file'] = "N/A"
                        
                    if base_event['action'] == 'drop':
                        # Для событий блокировки добавляем специальные метки
                        base_event['blocked'] = True
                        base_event['severity'] = 1  # Повышаем важность для блокировок
                        
                        # Переопределяем некоторые поля для ясности
                        if 'signature' not in base_event:
                            base_event['signature'] = f"GUI Blocked IP {base_event['src_ip']}"
                    
                    # ДЛЯ НАШИХ БЛОКИРОВОК - НАЧАЛО ИСПРАВЛЕНИЙ
                    if action == 'drop':
                        base_event['blocked'] = True
                        base_event['severity'] = max(base_event.get('severity', 0), 3)
                        
                        # Переопределяем сигнатуру для ясности
                        if 'signature' not in base_event:
                            base_event['signature'] = f"GUI Blocked IP {base_event['src_ip']}"
                
                    
                    events.append(base_event)
                except json.JSONDecodeError as e:
                    # Пытаемся восстановить неполный JSON
                    if line.endswith('}}') or line.endswith('}'):
                        try:
                            # Удаляем последнюю фигурную скобку и пробуем снова
                            recovered_line = line[:-1].strip()
                            if recovered_line.endswith(','):
                                recovered_line = recovered_line[:-1]
                            if recovered_line.endswith('}}'):
                                recovered_line = recovered_line[:-1]
                            
                            event = json.loads(recovered_line)
                            if 'event_type' in event:
                                # Если удалось восстановить, добавляем событие
                                events.append({
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'event_type': event.get('event_type', 'recovered'),
                                    'src_ip': event.get('src_ip', 'N/A'),
                                    'dest_ip': event.get('dest_ip', 'N/A'),
                                    'proto': event.get('proto', 'N/A'),
                                    'action': event.get('action', 'unknown'),
                                    'raw': recovered_line,
                                    'signature': 'Recovered Event',
                                    'category': 'Recovered',
                                    'severity': 1
                                })
                        except:
                            # Если не удалось восстановить, логируем как DEBUG
                            logging.debug(f"Неудачное восстановление JSON: {str(e)}\nСтрока: {line}")
                except KeyError as ke:
                    logging.debug(f"Отсутствует ключ в событии: {ke}\nСтрока: {line}")
                except Exception as e:
                    logging.debug(f"Ошибка парсинга события: {type(e).__name__}: {str(e)}\nСтрока: {line}")
        
        except Exception as e:
            logging.error(f"Ошибка чтения событий: {str(e)}\n{traceback.format_exc()}")
        
        return events
    
    def find_rule_file_by_sid(self, sid):
        """Находит файл правила по SID"""
        sid_str = str(sid)
        rule_files = self.get_rule_files()
        
        for filename in rule_files:
            filepath = os.path.join(self.rules_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        if f"sid:{sid_str};" in line:
                            return filename
            except Exception:
                continue
        return "Unknown"
    
    
    def load_config(self):
        """Загружает конфигурацию Suricata из файла"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logging.error(f"Ошибка чтения конфигурации: {str(e)}\n{traceback.format_exc()}")
            return ""
    
    def save_config(self, config_text):
        """Сохраняет конфигурацию Suricata в файл с обработкой прав доступа"""
        try:
            # Проверяем наличие обязательных YAML-директив
            yaml_header = "%YAML 1.1"
            separator = "---"
            
            # Разбиваем текст на строки для анализа
            lines = config_text.splitlines()
            has_yaml_directive = False
            has_separator = False
            
            # Проверяем первые строки на наличие обязательных директив
            if lines:
                if lines[0].strip() == yaml_header:
                    has_yaml_directive = True
                if len(lines) > 1 and lines[1].strip() == separator:
                    has_separator = True
            
            # Восстанавливаем отсутствующие директивы
            if not has_yaml_directive or not has_separator:
                # Добавляем недостающие элементы
                fixed_lines = []
                if not has_yaml_directive:
                    fixed_lines.append(yaml_header)
                if not has_separator:
                    fixed_lines.append(separator)
                
                # Добавляем оригинальное содержимое
                fixed_lines.extend(lines)
                config_text = "\n".join(fixed_lines)
            
            # Создаем резервную копию перед сохранением
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(self.backup_dir, f"suricata_backup_{timestamp}.yaml")
            
            # Копируем с правами администратора
            if not self.safe_write_file(backup_file, self.load_config()):
                logging.error("Не удалось создать резервную копию конфигурации")
            
            # Сохраняем новый конфиг с правами администратора
            return self.safe_write_file(self.config_file, config_text)
        except Exception as e:
            logging.error(f"Ошибка сохранения конфигурации: {str(e)}\n{traceback.format_exc()}")
            return False
    
   
    
    def validate_config(self, config_text):
        """Проверяет валидность конфигурации YAML"""
        try:
            yaml.safe_load(config_text)
            return True, "Конфигурация валидна"
        except yaml.YAMLError as e:
            error_msg = f"Ошибка в конфигурации:\n{str(e)}"
            return False, error_msg
        except Exception as e:
            error_msg = f"Неизвестная ошибка валидации:\n{str(e)}"
            return False, error_msg
    
    def start_suricata(self):
        if self.safe_service_action("start"):
            logging.info("Suricata запущена")
            return True
        return False
    
    def stop_suricata(self):
        if self.safe_service_action("stop"):
            logging.info("Suricata остановлена")
            return True
        return False
    
    def restart_suricata(self):
        if self.safe_service_action("restart"):
            logging.info("Suricata перезапущена")
            return True
        return False
    
    def get_rule_status(self, sid):
        """Возвращает статус правила по SID"""
        sid_str = str(sid)  # Нормализуем SID к строке
        
        # Ищем правило во всех файлах
        rule_files = self.get_rule_files()
        for filename in rule_files:
            rules = self.parse_rules(filename)
            for rule in rules:
                if rule['sid'] == sid_str:
                    # Определяем действие правила
                    action = "unknown"
                    if rule['enabled']:
                        parts = rule['raw'].split()
                        if parts:
                            action = parts[0]  # Первое слово - действие
                    return {
                        'enabled': rule['enabled'],
                        'action': action,
                        'file': rule['file']
                    }
        
        # Правило не найдено
        return {
            'enabled': False,
            'action': 'unknown',
            'file': None
        }

    def is_suricata_running(self):
        """Проверяет, работает ли Suricata"""
        try:
            status_info = win32serviceutil.QueryServiceStatus(self.service_name)
            return status_info[1] == win32service.SERVICE_RUNNING
        except pywintypes.error as e:
            if e.winerror == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                return False
            logging.error(f"Error checking Suricata status: {e.strerror}\n{traceback.format_exc()}")
            return False
        except Exception as e:
            logging.error(f"Error checking Suricata status: {str(e)}\n{traceback.format_exc()}")
            return False
        
    def service_exists(self):
        """Проверяет, существует ли служба"""
        try:
            win32serviceutil.QueryServiceStatus(self.service_name)
            return True
        except pywintypes.error as e:
            if e.winerror == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                return False
            logging.error(f"Error checking service existence: {e.strerror}\n{traceback.format_exc()}")
            return False
        except Exception as e:
            logging.error(f"Error checking service existence: {str(e)}\n{traceback.format_exc()}")
            return False