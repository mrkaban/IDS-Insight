# -*- coding: utf-8 -*-
import sys
import ctypes
from PyQt6.QtWidgets import QApplication
from gui import MainWindow

if __name__ == "__main__":
    # Проверка прав администратора
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, None, 1)
    
    app = QApplication(sys.argv)
    window = MainWindow()
    
    # Установка имени службы
    window.suricata.set_service_name("SuricataService")
    
    window.show()
    sys.exit(app.exec())
    
# необходимо реализовать: 
# 0) при отображении всех событий работает автообновление, хотя не должно

# 4) многопоточность при обработке событий в общем списке, при их загрузке