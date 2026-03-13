from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton,
    QMessageBox
)

from worker.native_terminal_launcher import NativeTerminalLauncher


class TerminalTab(QWidget):
    """Terminal tab that launches a native terminal session"""

    def __init__(self, parent_app):
        super().__init__()
        self.parent_app = parent_app
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.addStretch()

        # Info label
        info_label = QLabel("Launch a native terminal session for the current server connection.")
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_label.setStyleSheet("font-size: 14px; color: #555; margin-bottom: 20px;")
        layout.addWidget(info_label)

        # Launch button
        self.launch_btn = QPushButton("Access Native Terminal")
        self.launch_btn.setMinimumHeight(60)
        self.launch_btn.setMinimumWidth(300)
        self.launch_btn.setStyleSheet("""
            QPushButton {
                background-color: #2c3e50;
                color: white;
                font-size: 18px;
                font-weight: bold;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #34495e;
            }
            QPushButton:pressed {
                background-color: #1a252f;
            }
        """)
        self.launch_btn.clicked.connect(self.launch_terminal)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(self.launch_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        layout.addStretch()

    def launch_terminal(self):
        config = self.parent_app._get_current_config()
        hostname = config.get('ec2_host')
        username = config.get('ec2_user')
        key_path = config.get('ec2_key_path')

        if not hostname or not username:
            QMessageBox.warning(self, "Missing Info", "Please select or configure a server first.")
            return

        try:
            NativeTerminalLauncher.open_native_terminal(hostname, username, key_path=key_path)
            self.parent_app.showMinimized()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
