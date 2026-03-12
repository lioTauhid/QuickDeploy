import os
from pathlib import Path

from PyQt6.QtCore import QPoint
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton,
    QFileDialog, QMessageBox, QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QInputDialog, QMenu
)

from core.ssh_manager import SSHConnectionManager
from ui.file_edit_dialog import FileEditDialog
from worker.file_operation_worker import FileOperationWorker


class FileBrowserTab(QWidget):
    """File browser and management tab"""

    def __init__(self, ssh_manager: SSHConnectionManager):
        super().__init__()
        self.ssh_manager = ssh_manager
        self.current_path = "/"
        self.path_history = ["/"]
        self.history_index = 0
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Toolbar
        toolbar = QHBoxLayout()

        # Back button
        back_btn = QPushButton("⬅ Back")
        back_btn.clicked.connect(self.go_back)
        toolbar.addWidget(back_btn)

        self.path_input = QLineEdit("/")
        self.path_input.returnPressed.connect(self.refresh_directory)
        toolbar.addWidget(QLabel("Path:"))
        toolbar.addWidget(self.path_input)

        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_directory)
        toolbar.addWidget(refresh_btn)

        mkdir_btn = QPushButton("📁 New Folder")
        mkdir_btn.clicked.connect(self.create_directory)
        toolbar.addWidget(mkdir_btn)

        upload_btn = QPushButton("⬆ Upload")
        upload_btn.clicked.connect(self.upload_file)
        toolbar.addWidget(upload_btn)

        layout.addLayout(toolbar)

        # File list
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(4)
        self.file_table.setHorizontalHeaderLabels(["Name", "Type", "Size", "Permissions"])
        self.file_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.file_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self.show_context_menu)
        self.file_table.itemDoubleClicked.connect(self.on_item_double_clicked)
        layout.addWidget(self.file_table)

        # Progress bar
        self.file_progress = QProgressBar()
        self.file_progress.setVisible(False)
        layout.addWidget(self.file_progress)

        # Status
        self.status_label = QLabel("Connect to server to browse files")
        layout.addWidget(self.status_label)

    def go_back(self):
        """Navigate to parent directory"""
        if self.current_path == "/":
            self.status_label.setText("Already at root directory")
            return

        # Get parent directory - cross-platform compatible
        parent_path = str(Path(self.current_path).parent)
        if not parent_path or parent_path == ".":
            parent_path = "/"

        self.path_input.setText(parent_path)
        self.refresh_directory()

    def refresh_directory(self):
        if not self.ssh_manager.is_connected:
            self.status_label.setText("Error: Not connected to server")
            return

        path = self.path_input.text()
        self.current_path = path

        self.worker = FileOperationWorker(self.ssh_manager, "list", path=path)
        self.worker.finished_signal.connect(self.update_file_list)
        self.worker.start()

    def update_file_list(self, success: bool, output: str):
        if not success:
            self.status_label.setText(f"Error: {output}")
            return

        self.file_table.setRowCount(0)
        lines = output.strip().split('\n')[1:]  # Skip first line (total)

        for line in lines:
            parts = line.split()
            if len(parts) < 9:
                continue

            permissions = parts[0]
            size = parts[4]
            name = ' '.join(parts[8:])

            if name in ['.', '..']:
                continue

            file_type = "Directory" if permissions.startswith('d') else "File"

            row = self.file_table.rowCount()
            self.file_table.insertRow(row)
            self.file_table.setItem(row, 0, QTableWidgetItem(name))
            self.file_table.setItem(row, 1, QTableWidgetItem(file_type))
            self.file_table.setItem(row, 2, QTableWidgetItem(size))
            self.file_table.setItem(row, 3, QTableWidgetItem(permissions))

        self.status_label.setText(f"Showing {self.file_table.rowCount()} items in {self.current_path}")

    def upload_file(self):
        if not self.ssh_manager.is_connected:
            QMessageBox.warning(self, "Error", "Not connected to server")
            return

        local_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if not local_path:
            return

        filename = os.path.basename(local_path)
        remote_path = f"{self.current_path}/{filename}".replace('//', '/')

        self.file_progress.setVisible(True)
        self.file_progress.setValue(0)

        self.worker = FileOperationWorker(
            self.ssh_manager, "upload",
            local_path=local_path,
            remote_path=remote_path
        )
        self.worker.progress_signal.connect(self.file_progress.setValue)
        self.worker.finished_signal.connect(self.on_file_operation_finished)
        self.worker.start()

    def download_file(self, filename: str):
        remote_path = f"{self.current_path}/{filename}".replace('//', '/')
        local_path, _ = QFileDialog.getSaveFileName(self, "Save File", filename)

        if not local_path:
            return

        self.file_progress.setVisible(True)
        self.file_progress.setValue(0)

        self.worker = FileOperationWorker(
            self.ssh_manager, "download",
            remote_path=remote_path,
            local_path=local_path
        )
        self.worker.progress_signal.connect(self.file_progress.setValue)
        self.worker.finished_signal.connect(self.on_file_operation_finished)
        self.worker.start()

    def delete_file(self, filename: str):
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete {filename}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            remote_path = f"{self.current_path}/{filename}".replace('//', '/')

            self.worker = FileOperationWorker(
                self.ssh_manager, "delete",
                remote_path=remote_path
            )
            self.worker.finished_signal.connect(self.on_file_operation_finished)
            self.worker.start()

    def rename_file(self, old_filename: str):
        """Rename a file or directory"""
        new_filename, ok = QInputDialog.getText(
            self, "Rename",
            f"Enter new name for '{old_filename}':",
            text=old_filename
        )

        if ok and new_filename and new_filename != old_filename:
            old_path = f"{self.current_path}/{old_filename}".replace('//', '/')
            new_path = f"{self.current_path}/{new_filename}".replace('//', '/')

            self.worker = FileOperationWorker(
                self.ssh_manager, "rename",
                old_path=old_path,
                new_path=new_path
            )
            self.worker.finished_signal.connect(self.on_file_operation_finished)
            self.worker.start()

    def edit_file(self, filename: str):
        """Open file editor dialog"""
        remote_path = f"{self.current_path}/{filename}".replace('//', '/')

        # Check if it's a file (not a directory)
        row = None
        for i in range(self.file_table.rowCount()):
            if self.file_table.item(i, 0).text() == filename:
                row = i
                break

        if row is not None:
            file_type = self.file_table.item(row, 1).text()
            if file_type == "Directory":
                QMessageBox.warning(self, "Error", "Cannot edit a directory")
                return

        # Open edit dialog
        dialog = FileEditDialog(self, self.ssh_manager, filename, remote_path)
        dialog.exec()

        # Refresh file list after editing
        self.refresh_directory()

    def create_directory(self):
        dir_name, ok = QInputDialog.getText(self, "New Directory", "Directory name:")
        if ok and dir_name:
            remote_path = f"{self.current_path}/{dir_name}".replace('//', '/')

            self.worker = FileOperationWorker(
                self.ssh_manager, "mkdir",
                remote_path=remote_path
            )
            self.worker.finished_signal.connect(self.on_file_operation_finished)
            self.worker.start()

    def on_file_operation_finished(self, success: bool, message: str):
        self.file_progress.setVisible(False)

        if success:
            self.status_label.setText(message)
            self.refresh_directory()
        else:
            self.status_label.setText(f"Error: {message}")
            QMessageBox.critical(self, "Error", message)

    def on_item_double_clicked(self, item):
        row = item.row()
        name = self.file_table.item(row, 0).text()
        file_type = self.file_table.item(row, 1).text()

        if file_type == "Directory":
            new_path = f"{self.current_path}/{name}".replace('//', '/')
            self.path_input.setText(new_path)
            self.refresh_directory()
        else:
            # Open file editor for files
            self.edit_file(name)

    def show_context_menu(self, position: QPoint):
        item = self.file_table.itemAt(position)
        if not item:
            return

        row = item.row()
        filename = self.file_table.item(row, 0).text()
        file_type = self.file_table.item(row, 1).text()

        menu = QMenu()

        if file_type == "File":
            download_action = menu.addAction("📥 Download")
            download_action.triggered.connect(lambda: self.download_file(filename))

            edit_action = menu.addAction("✏️ Edit")
            edit_action.triggered.connect(lambda: self.edit_file(filename))

        rename_action = menu.addAction("🏷️ Rename")
        rename_action.triggered.connect(lambda: self.rename_file(filename))

        delete_action = menu.addAction("🗑️ Delete")
        delete_action.triggered.connect(lambda: self.delete_file(filename))

        menu.exec(self.file_table.viewport().mapToGlobal(position))
