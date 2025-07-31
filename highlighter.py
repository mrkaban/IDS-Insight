# -*- coding: utf-8 -*-
import re
from PyQt6.QtCore import QRegularExpression
from PyQt6.QtGui import (
    QSyntaxHighlighter, QTextCharFormat, QColor, 
    QFont, QTextDocument, QRegularExpressionValidator
)

class JsonHighlighter(QSyntaxHighlighter):
    """Подсветка синтаксиса для JSON"""
    def __init__(self, document):
        super().__init__(document)
        
        # Форматы для разных элементов JSON
        self.formats = {
            'key': QTextCharFormat(),
            'string': QTextCharFormat(),
            'number': QTextCharFormat(),
            'bool': QTextCharFormat(),
            'null': QTextCharFormat()
        }
        
        # Настройка цветов
        self.formats['key'].setForeground(QColor(200, 0, 0))  # Красный для ключей
        self.formats['string'].setForeground(QColor(0, 150, 0))  # Зеленый для строк
        self.formats['number'].setForeground(QColor(0, 0, 255))  # Синий для чисел
        self.formats['bool'].setForeground(QColor(150, 0, 150))  # Фиолетовый для булевых
        self.formats['null'].setForeground(QColor(150, 150, 150))  # Серый для null
        
    def highlightBlock(self, text):
        """Применяет подсветку к блоку текста"""
        # Регулярные выражения для элементов JSON
        patterns = {
            'key': r'"[^"]*"\s*:',
            'string': r'"[^"]*"',
            'number': r'\b-?\d+\.?\d*\b',
            'bool': r'\b(true|false)\b',
            'null': r'\bnull\b'
        }
        
        # Применяем подсветку для каждого типа
        for name, pattern in patterns.items():
            expression = re.compile(pattern)
            for match in expression.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, self.formats[name])

class YamlHighlighter(QSyntaxHighlighter):
    """Подсветка синтаксиса для YAML"""
    def __init__(self, document):
        super().__init__(document)
        
        # Форматы для разных элементов YAML
        self.formats = {
            'key': QTextCharFormat(),
            'string': QTextCharFormat(),
            'number': QTextCharFormat(),
            'comment': QTextCharFormat(),
            'section': QTextCharFormat()
        }
        
        # Настройка цветов
        self.formats['key'].setForeground(QColor(0, 0, 200))  # Синий для ключей
        self.formats['string'].setForeground(QColor(0, 150, 0))  # Зеленый для строк
        self.formats['number'].setForeground(QColor(200, 0, 200))  # Фиолетовый для чисел
        self.formats['comment'].setForeground(QColor(150, 150, 150))  # Серый для комментариев
        self.formats['section'].setForeground(QColor(200, 0, 0))  # Красный для секций
        self.formats['section'].setFontWeight(QFont.Weight.Bold)
        
        # Регулярные выражения
        self.rules = [
            (r'#.*$', 'comment'),
            (r'^[\w\-]+:', 'key'),
            (r':\s*[\w\-]+', 'key'),
            (r':\s*[\'"]?[\w\-\.]+[\'"]?$', 'string'),
            (r':\s*\d+', 'number'),
            (r':\s*\d+\.\d+', 'number'),
            (r'^\s*[\w\-]+\s*:', 'section')
        ]
        
        # Компилируем регулярные выражения
        self.compiled_rules = []
        for pattern, fmt in self.rules:
            self.compiled_rules.append((
                QRegularExpression(pattern), 
                self.formats[fmt]
            ))
        
    def highlightBlock(self, text):
        """Применяет подсветку к блоку текста"""
        for regex, fmt in self.compiled_rules:
            match_iterator = regex.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), fmt)