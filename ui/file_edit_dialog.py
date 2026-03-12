from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QPushButton,
    QMessageBox, QDialog
)

from core.ssh_manager import SSHConnectionManager
from worker.file_operation_worker import FileOperationWorker


class FileEditDialog(QDialog):
    """Dialog for editing remote files"""

    def __init__(self, parent, ssh_manager: SSHConnectionManager, filename: str, filepath: str):
        super().__init__(parent)
        self.ssh_manager = ssh_manager
        self.filename = filename
        self.filepath = filepath
        self.original_content = ""
        self.worker = None
        self.init_ui()
        self.load_file()

    def init_ui(self):
        """Initialize the dialog UI"""
        self.setWindowTitle(f"Edit: {self.filename}")
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout(self)

        # File path label
        path_label = QLabel(f"File: {self.filepath}")
        path_label.setStyleSheet("color: #666; font-size: 10px;")
        layout.addWidget(path_label)

        # Text editor
        self.text_editor = QTextEdit()
        self.text_editor.setFont(QFont("Courier", 10))
        layout.addWidget(self.text_editor)

        # Status label
        self.status_label = QLabel("Loading file...")
        layout.addWidget(self.status_label)

        # Buttons
        button_layout = QHBoxLayout()

        save_btn = QPushButton("💾 Save")
        save_btn.clicked.connect(self.save_file)
        button_layout.addWidget(save_btn)

        close_btn = QPushButton("✕ Close")
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

    def load_file(self):
        """Load file content from remote server"""
        self.text_editor.setEnabled(False)
        self.status_label.setText("Loading file...")

        self.worker = FileOperationWorker(self.ssh_manager, "read", remote_path=self.filepath)
        self.worker.finished_signal.connect(self.on_file_loaded)
        self.worker.start()

    def on_file_loaded(self, success: bool, content: str):
        """Handle file loaded"""
        self.text_editor.setEnabled(True)

        if success:
            self.original_content = content
            self.text_editor.setPlainText(content)
            self.status_label.setText(f"File loaded ({len(content)} bytes)")
        else:
            self.status_label.setText(f"Error: {content}")
            QMessageBox.critical(self, "Error", f"Failed to load file: {content}")

    def save_file(self):
        """Save file content to remote server"""
        content = self.text_editor.toPlainText()

        if content == self.original_content:
            self.status_label.setText("No changes to save")
            return

        reply = QMessageBox.question(
            self, "Confirm Save",
            f"Save changes to {self.filename}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.text_editor.setEnabled(False)
            self.status_label.setText("Saving file...")

            self.worker = FileOperationWorker(
                self.ssh_manager, "write",
                remote_path=self.filepath,
                content=content
            )
            self.worker.finished_signal.connect(self.on_file_saved)
            self.worker.start()

    def on_file_saved(self, success: bool, message: str):
        """Handle file saved"""
        self.text_editor.setEnabled(True)

        if success:
            self.original_content = self.text_editor.toPlainText()
            self.status_label.setText(f"File saved successfully")
            QMessageBox.information(self, "Success", "File saved successfully!")
        else:
            self.status_label.setText(f"Error: {message}")
            QMessageBox.critical(self, "Error", f"Failed to save file: {message}")
