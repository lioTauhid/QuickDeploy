import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from PyQt6.QtCore import QPoint
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QTextEdit, QPushButton,
    QFileDialog, QMessageBox, QProgressBar, QGroupBox,
    QScrollArea, QSplitter, QCheckBox, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QInputDialog, QMenu, QComboBox, QDialog
)
from paramiko import SSHClient, AutoAddPolicy, SFTPClient


class ConfigManager:
    """Manages configuration files in OS-specific hidden directory"""

    def __init__(self):
        self.config_dir = self._get_config_directory()
        self._ensure_config_directory()

    def _get_config_directory(self) -> Path:
        """Get OS-specific configuration directory"""
        if sys.platform == 'win32':
            # Windows: C:\Users\Username\AppData\Local\DeploymentTool
            base_dir = os.getenv('LOCALAPPDATA', os.path.expanduser('~'))
            config_dir = Path(base_dir) / 'DeploymentTool'
        elif sys.platform == 'darwin':
            # macOS: ~/Library/Application Support/DeploymentTool
            config_dir = Path.home() / 'Library' / 'Application Support' / 'DeploymentTool'
        else:
            # Linux/Unix: ~/.config/deployment-tool
            config_dir = Path.home() / '.config' / 'deployment-tool'

        return config_dir

    def _ensure_config_directory(self):
        """Create config directory if it doesn't exist"""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"Warning: Could not create config directory: {e}")

    def list_configs(self) -> List[str]:
        """List all saved configuration files"""
        try:
            if not self.config_dir.exists():
                return []

            configs = []
            for file in self.config_dir.glob('*.json'):
                configs.append(file.stem)  # Get filename without extension

            return sorted(configs)
        except Exception as e:
            print(f"Error listing configs: {e}")
            return []

    def save_config(self, name: str, config: Dict) -> tuple[bool, str]:
        """Save configuration to file"""
        try:
            # Sanitize filename
            safe_name = "".join(c for c in name if c.isalnum() or c in ('-', '_', ' ')).strip()
            if not safe_name:
                return False, "Invalid configuration name"

            file_path = self.config_dir / f"{safe_name}.json"

            with open(file_path, 'w') as f:
                json.dump(config, f, indent=4)

            return True, f"Configuration saved: {safe_name}"
        except Exception as e:
            return False, f"Failed to save configuration: {str(e)}"

    def load_config(self, name: str) -> tuple[bool, Dict, str]:
        """Load configuration from file"""
        try:
            file_path = self.config_dir / f"{name}.json"

            if not file_path.exists():
                return False, {}, f"Configuration not found: {name}"

            with open(file_path, 'r') as f:
                config = json.load(f)

            return True, config, f"Configuration loaded: {name}"
        except Exception as e:
            return False, {}, f"Failed to load configuration: {str(e)}"

    def delete_config(self, name: str) -> tuple[bool, str]:
        """Delete a configuration file"""
        try:
            file_path = self.config_dir / f"{name}.json"

            if not file_path.exists():
                return False, f"Configuration not found: {name}"

            file_path.unlink()
            return True, f"Configuration deleted: {name}"
        except Exception as e:
            return False, f"Failed to delete configuration: {str(e)}"

    def get_config_path(self) -> str:
        """Get the configuration directory path"""
        return str(self.config_dir)


class SSHConnectionManager:
    """Manages persistent SSH connection for terminal and file operations"""

    def __init__(self):
        self.ssh_client: Optional[SSHClient] = None
        self.sftp_client: Optional[SFTPClient] = None
        self.is_connected = False
        self.shell_channel = None

    def connect(self, hostname: str, username: str, key_filename: str, timeout: int = 30):
        """Establish SSH connection"""
        try:
            self.ssh_client = SSHClient()
            self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())
            key_path = os.path.expanduser(key_filename)

            if not os.path.exists(key_path):
                raise Exception(f"SSH key not found: {key_path}")

            self.ssh_client.connect(
                hostname=hostname,
                username=username,
                key_filename=key_path,
                timeout=timeout
            )

            self.sftp_client = self.ssh_client.open_sftp()
            self.is_connected = True
            return True, "Connected successfully"
        except Exception as e:
            self.is_connected = False
            return False, str(e)

    def disconnect(self):
        """Close SSH connection"""
        try:
            if self.shell_channel:
                self.shell_channel.close()
            if self.sftp_client:
                self.sftp_client.close()
            if self.ssh_client:
                self.ssh_client.close()
            self.is_connected = False
            self.shell_channel = None
        except:
            pass

    def get_shell_channel(self):
        """Get or create interactive shell channel"""
        if not self.is_connected or not self.ssh_client:
            return None

        if self.shell_channel is None or self.shell_channel.closed:
            self.shell_channel = self.ssh_client.invoke_shell(
                term='xterm-256color',
                width=120,
                height=40
            )
            # Initialize shell with proper settings
            self.shell_channel.send('export TERM=xterm-256color\n')
            self.shell_channel.send('export PS1="$ "\n')
            self.shell_channel.send('unset LS_COLORS\n')
            self.shell_channel.send('shopt -s expand_aliases 2>/dev/null\n')
            # Source bash profile and aliases
            self.shell_channel.send('source ~/.bashrc 2>/dev/null; source ~/.bash_aliases 2>/dev/null\n')
            # Small delay to ensure shell is ready
            import time
            time.sleep(0.5)

        return self.shell_channel

    def execute_command(self, command: str):
        """Execute a single command and return output"""
        if not self.is_connected or not self.ssh_client:
            return False, "Not connected", ""

        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command, get_pty=True)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            return True, output, error
        except Exception as e:
            return False, "", str(e)

    def read_file(self, remote_path: str) -> tuple[bool, str, str]:
        """Read file content via SFTP"""
        try:
            if not self.sftp_client:
                return False, "", "SFTP not available"

            with self.sftp_client.file(remote_path, 'r') as f:
                content = f.read().decode('utf-8', errors='ignore')
            return True, content, ""
        except Exception as e:
            return False, "", str(e)

    def write_file(self, remote_path: str, content: str) -> tuple[bool, str]:
        """Write file content via SFTP"""
        try:
            if not self.sftp_client:
                return False, "SFTP not available"

            with self.sftp_client.file(remote_path, 'w') as f:
                f.write(content.encode('utf-8'))
            return True, "File saved successfully"
        except Exception as e:
            return False, str(e)


class NativeTerminalLauncher:
    """Cross-platform native terminal launcher for SSH connections"""

    @staticmethod
    def open_native_terminal(hostname, username, key_path=None, password=None):
        system = platform.system()

        try:
            if system == "Windows":
                NativeTerminalLauncher._open_windows_terminal(hostname, username, key_path, password)
            elif system == "Darwin":  # macOS
                NativeTerminalLauncher._open_macos_terminal(hostname, username, key_path, password)
            elif system == "Linux":
                NativeTerminalLauncher._open_linux_terminal(hostname, username, key_path, password)
            else:
                raise Exception(f"Unsupported operating system: {system}")
        except Exception as e:
            raise Exception(f"Failed to open native terminal: {e}")

    @staticmethod
    def _open_windows_terminal(hostname, username, key_path=None, password=None):
        ssh_cmd = f'ssh'
        if key_path:
            ssh_cmd += f' -i "{key_path}"'
        ssh_cmd += f' {username}@{hostname}'

        # Open Command Prompt and execute SSH command
        subprocess.Popen(f'start cmd /k {ssh_cmd}', shell=True)

    @staticmethod
    def _open_macos_terminal(hostname, username, key_path=None, password=None):
        ssh_cmd = f'ssh'
        if key_path:
            ssh_cmd += f' -i "{key_path}"'
        ssh_cmd += f' {username}@{hostname}'

        # Use osascript to open Terminal.app and run SSH command
        applescript = f'''
        tell application "Terminal"
            activate
            do script "{ssh_cmd}"
        end tell
        '''

        subprocess.Popen(['osascript', '-e', applescript])

    @staticmethod
    def _open_linux_terminal(hostname, username, key_path=None, password=None):
        ssh_cmd = f'ssh'
        if key_path:
            ssh_cmd += f' -i "{key_path}"'
        ssh_cmd += f' {username}@{hostname}'

        # List of common terminal emulators to try
        terminals = [
            ['gnome-terminal', '--', 'bash', '-c', f'{ssh_cmd}; exec bash'],
            ['xterm', '-e', ssh_cmd],
            ['konsole', '-e', ssh_cmd],
            ['xfce4-terminal', '-e', ssh_cmd],
            ['mate-terminal', '-e', ssh_cmd],
            ['lxterminal', '-e', ssh_cmd],
            ['tilix', '-e', ssh_cmd],
            ['terminator', '-e', ssh_cmd],
        ]

        for terminal_cmd in terminals:
            try:
                subprocess.Popen(terminal_cmd)
                return
            except FileNotFoundError:
                continue

        # If no terminal found, raise error
        raise Exception("No supported terminal emulator found. Please install gnome-terminal, xterm, or konsole.")


class FileOperationWorker(QThread):
    """Worker thread for file operations to keep UI responsive"""
    finished_signal = pyqtSignal(bool, str)
    progress_signal = pyqtSignal(int)

    def __init__(self, ssh_manager: SSHConnectionManager, operation: str, **kwargs):
        super().__init__()
        self.ssh_manager = ssh_manager
        self.operation = operation
        self.kwargs = kwargs

    def run(self):
        try:
            if self.operation == "list":
                self._list_directory()
            elif self.operation == "upload":
                self._upload_file()
            elif self.operation == "download":
                self._download_file()
            elif self.operation == "delete":
                self._delete_file()
            elif self.operation == "mkdir":
                self._create_directory()
            elif self.operation == "rename":
                self._rename_file()
            elif self.operation == "read":
                self._read_file()
            elif self.operation == "write":
                self._write_file()
        except Exception as e:
            self.finished_signal.emit(False, str(e))

    def _list_directory(self):
        path = self.kwargs['path']
        success, output, error = self.ssh_manager.execute_command(f"ls -la {path}")
        if success:
            self.finished_signal.emit(True, output)
        else:
            self.finished_signal.emit(False, error)

    def _upload_file(self):
        local_path = self.kwargs['local_path']
        remote_path = self.kwargs['remote_path']

        def progress_callback(transferred, total):
            if total > 0:
                progress = int((transferred / total) * 100)
                self.progress_signal.emit(progress)

        self.ssh_manager.sftp_client.put(local_path, remote_path, callback=progress_callback)
        self.finished_signal.emit(True, f"Uploaded {os.path.basename(local_path)}")

    def _download_file(self):
        remote_path = self.kwargs['remote_path']
        local_path = self.kwargs['local_path']

        def progress_callback(transferred, total):
            if total > 0:
                progress = int((transferred / total) * 100)
                self.progress_signal.emit(progress)

        self.ssh_manager.sftp_client.get(remote_path, local_path, callback=progress_callback)
        self.finished_signal.emit(True, f"Downloaded {os.path.basename(remote_path)}")

    def _delete_file(self):
        remote_path = self.kwargs['remote_path']
        success, output, error = self.ssh_manager.execute_command(f"rm -rf {remote_path}")
        if success:
            self.finished_signal.emit(True, f"Deleted {remote_path}")
        else:
            self.finished_signal.emit(False, error)

    def _create_directory(self):
        remote_path = self.kwargs['remote_path']
        success, output, error = self.ssh_manager.execute_command(f"mkdir -p {remote_path}")
        if success:
            self.finished_signal.emit(True, f"Created directory {remote_path}")
        else:
            self.finished_signal.emit(False, error)

    def _rename_file(self):
        old_path = self.kwargs['old_path']
        new_path = self.kwargs['new_path']
        success, output, error = self.ssh_manager.execute_command(f"mv {old_path} {new_path}")
        if success:
            self.finished_signal.emit(True, f"Renamed {old_path} to {new_path}")
        else:
            self.finished_signal.emit(False, error)

    def _read_file(self):
        remote_path = self.kwargs['remote_path']
        success, content, error = self.ssh_manager.read_file(remote_path)
        if success:
            self.finished_signal.emit(True, content)
        else:
            self.finished_signal.emit(False, error)

    def _write_file(self):
        remote_path = self.kwargs['remote_path']
        content = self.kwargs['content']
        success, message = self.ssh_manager.write_file(remote_path, content)
        self.finished_signal.emit(success, message)


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
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


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


class DeploymentWorker(QThread):
    """Worker thread for handling SSH deployment operations"""
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, config: Dict):
        super().__init__()
        self.config = config

    def run(self):
        """Execute the deployment process"""
        try:
            self.log_signal.emit("🚀 Starting deployment...")
            self.progress_signal.emit(10)

            ssh = SSHClient()
            ssh.set_missing_host_key_policy(AutoAddPolicy())

            self.log_signal.emit(f"📡 Connecting to {self.config['ec2_host']}...")
            key_path = os.path.expanduser(self.config['ec2_key_path'])

            if not os.path.exists(key_path):
                raise Exception(f"SSH key not found: {key_path}")

            ssh.connect(
                hostname=self.config['ec2_host'],
                username=self.config['ec2_user'],
                key_filename=key_path,
                timeout=30
            )

            self.progress_signal.emit(30)
            self.log_signal.emit("✅ Connected successfully!")

            commands = self._prepare_commands()

            for i, command in enumerate(commands):
                self.log_signal.emit(f"📋 Executing: {command[:50]}...")
                stdin, stdout, stderr = ssh.exec_command(command)

                while True:
                    line = stdout.readline()
                    if not line:
                        break
                    self.log_signal.emit(line.strip())

                error_output = stderr.read().decode()
                if error_output:
                    self.log_signal.emit(f"⚠️ Warning: {error_output}")

                progress = 30 + (i + 1) * (60 / len(commands))
                self.progress_signal.emit(int(progress))

            ssh.close()
            self.progress_signal.emit(100)
            self.log_signal.emit("✅ Deployment completed successfully!")
            self.finished_signal.emit(True, "Deployment completed successfully!")

        except Exception as e:
            error_msg = f"❌ Deployment failed: {str(e)}"
            self.log_signal.emit(error_msg)
            self.finished_signal.emit(False, error_msg)

    def _prepare_commands(self) -> List[str]:
        """Prepare the list of commands to execute on the remote server"""
        app_dir = self.config['app_dir']
        git_user = self.config['git_user']
        git_token = self.config['git_token']
        git_repo = self.config['git_repo']
        branch = self.config['branch']

        # Remove https:// or http:// from git_repo if present
        git_repo = git_repo.replace('https://', '').replace('http://', '')

        commands = [
            f"echo '📂 Navigating to app directory...'",
            f"if [ -d '{app_dir}/.git' ]; then "
            f"echo 'Pulling latest changes...'; "
            f"cd {app_dir}; "
            f"git reset --hard; "
            f"git pull https://{git_user}:{git_token}@{git_repo} {branch}; "
            f"else "
            f"echo 'Fresh clone...'; "
            f"rm -rf {app_dir}; "
            f"git clone -b {branch} https://{git_user}:{git_token}@{git_repo} {app_dir}; "
            f"cd {app_dir}; "
            f"fi"
        ]

        if self.config.get('install_commands'):
            commands.append("echo '📦 Installing dependencies...'")
            for cmd in self.config['install_commands']:
                if cmd.strip():
                    commands.append(f"cd {app_dir} && {cmd}")

        if self.config.get('migration_enabled', False) and self.config.get('migration_commands'):
            commands.append("echo '🔄 Running migrations...'")
            for cmd in self.config['migration_commands']:
                if cmd.strip():
                    commands.append(f"cd {app_dir} && {cmd}")

        if self.config.get('run_commands'):
            commands.append("echo '🚀 Starting application...'")
            for cmd in self.config['run_commands']:
                if cmd.strip():
                    commands.append(cmd)

        return commands


class DeploymentApp(QMainWindow):
    """Main application window with enhanced features"""

    def __init__(self):
        super().__init__()
        self.config = {}
        self.worker = None
        self.ssh_manager = SSHConnectionManager()
        self.config_manager = ConfigManager()
        self.current_config_name = None
        self.init_ui()
        self._load_config_list()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("QuickDeploy (Remote management, CI-CD)")
        self.setGeometry(100, 100, 1400, 900)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Connection toolbar
        conn_toolbar = self._create_connection_toolbar()
        main_layout.addLayout(conn_toolbar)

        # Tab widget for different features
        self.tabs = QTabWidget()

        # Deployment tab
        deployment_tab = self._create_deployment_tab()
        self.tabs.addTab(deployment_tab, "⚙️ Deployment")

        # Terminal tab
        self.terminal_tab = TerminalTab(self)
        self.tabs.addTab(self.terminal_tab, "💻 Terminal")

        # File browser tab
        self.file_browser_tab = FileBrowserTab(self.ssh_manager)
        self.tabs.addTab(self.file_browser_tab, "📁 File Browser")

        main_layout.addWidget(self.tabs)

        self.statusBar().showMessage(f"Ready - Config directory: {self.config_manager.get_config_path()}")

    def _create_connection_toolbar(self) -> QHBoxLayout:
        """Create connection status toolbar"""
        layout = QHBoxLayout()

        # Config selector section
        config_selector_layout = QHBoxLayout()
        config_selector_layout.addWidget(QLabel("Saved Configs:"))

        self.config_dropdown = QComboBox()
        self.config_dropdown.addItem("-- New Configuration --")
        self.config_dropdown.currentIndexChanged.connect(self._on_config_selected)
        config_selector_layout.addWidget(self.config_dropdown)

        delete_config_btn = QPushButton("🗑️ Delete")
        delete_config_btn.clicked.connect(self._delete_current_config)
        config_selector_layout.addWidget(delete_config_btn)

        layout.addLayout(config_selector_layout)
        layout.addSpacing(20)

        self.connection_status = QLabel("● Disconnected")
        self.connection_status.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(self.connection_status)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.toggle_connection)
        layout.addWidget(self.connect_btn)

        layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        return layout

    def toggle_connection(self):
        """Connect or disconnect from server"""
        if self.ssh_manager.is_connected:
            self.ssh_manager.disconnect()
            self.connection_status.setText("● Disconnected")
            self.connection_status.setStyleSheet("color: red; font-weight: bold;")
            self.connect_btn.setText("Connect")
            self.statusBar().showMessage("Disconnected from server")
        else:
            # Get connection details from config
            config = self._get_current_config()
            if not all([config.get('ec2_host'), config.get('ec2_user'), config.get('ec2_key_path')]):
                QMessageBox.warning(self, "Missing Info", "Please fill in EC2 connection details first")
                return

            success, message = self.ssh_manager.connect(
                hostname=config['ec2_host'],
                username=config['ec2_user'],
                key_filename=config['ec2_key_path']
            )

            if success:
                self.connection_status.setText("● Connected")
                self.connection_status.setStyleSheet("color: green; font-weight: bold;")
                self.connect_btn.setText("Disconnect")
                self.statusBar().showMessage(f"Connected to {config['ec2_host']}")

                # Refresh file browser
                self.file_browser_tab.refresh_directory()
            else:
                QMessageBox.critical(self, "Connection Failed", message)

    def _create_deployment_tab(self) -> QWidget:
        """Create the original deployment tab"""
        widget = QWidget()
        layout = QHBoxLayout(widget)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        config_widget = self._create_config_widget()
        splitter.addWidget(config_widget)

        log_widget = self._create_log_widget()
        splitter.addWidget(log_widget)

        splitter.setSizes([600, 600])
        layout.addWidget(splitter)

        return widget

    def _create_config_widget(self) -> QWidget:
        """Create the configuration input widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        title = QLabel("Deployment Configuration")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # Scroll area for form
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        form_container = QWidget()
        form_layout = QVBoxLayout(form_container)

        # EC2 Section
        ec2_group = QGroupBox("EC2 Connection")
        ec2_layout = QGridLayout()

        self.ec2_host = QLineEdit()
        self.ec2_user = QLineEdit()
        self.ec2_key_path = QLineEdit()

        key_browse_btn = QPushButton("Browse")
        key_browse_btn.clicked.connect(lambda: self._browse_file(self.ec2_key_path))

        ec2_layout.addWidget(QLabel("Host:"), 0, 0)
        ec2_layout.addWidget(self.ec2_host, 0, 1, 1, 2)
        ec2_layout.addWidget(QLabel("User:"), 1, 0)
        ec2_layout.addWidget(self.ec2_user, 1, 1, 1, 2)
        ec2_layout.addWidget(QLabel("Key Path:"), 2, 0)
        ec2_layout.addWidget(self.ec2_key_path, 2, 1)
        ec2_layout.addWidget(key_browse_btn, 2, 2)

        ec2_group.setLayout(ec2_layout)
        form_layout.addWidget(ec2_group)

        # Git Section
        git_group = QGroupBox("Git Repository")
        git_layout = QGridLayout()

        self.git_user = QLineEdit()
        self.git_token = QLineEdit()
        self.git_token.setEchoMode(QLineEdit.EchoMode.Password)
        self.git_repo = QLineEdit()
        self.branch = QLineEdit("main")

        git_layout.addWidget(QLabel("Git User:"), 0, 0)
        git_layout.addWidget(self.git_user, 0, 1)
        git_layout.addWidget(QLabel("Git Token:"), 1, 0)
        git_layout.addWidget(self.git_token, 1, 1)
        git_layout.addWidget(QLabel("Repo URL:"), 2, 0)
        git_layout.addWidget(self.git_repo, 2, 1)
        git_layout.addWidget(QLabel("Branch:"), 3, 0)
        git_layout.addWidget(self.branch, 3, 1)

        git_group.setLayout(git_layout)
        form_layout.addWidget(git_group)

        # App Section
        app_group = QGroupBox("Application Settings")
        app_layout = QGridLayout()

        self.app_dir = QLineEdit()
        self.install_cmds = QTextEdit()
        self.install_cmds.setMaximumHeight(60)
        self.run_cmds = QTextEdit()
        self.run_cmds.setMaximumHeight(60)

        app_layout.addWidget(QLabel("App Directory:"), 0, 0)
        app_layout.addWidget(self.app_dir, 0, 1)
        app_layout.addWidget(QLabel("Install Commands:"), 1, 0)
        app_layout.addWidget(self.install_cmds, 1, 1)
        app_layout.addWidget(QLabel("Run Commands:"), 2, 0)
        app_layout.addWidget(self.run_cmds, 2, 1)

        app_group.setLayout(app_layout)
        form_layout.addWidget(app_group)

        # Migration Section
        mig_group = QGroupBox("Database Migrations")
        mig_layout = QVBoxLayout()

        self.mig_enabled = QCheckBox("Enable Migrations")
        self.mig_cmds = QTextEdit()
        self.mig_cmds.setMaximumHeight(60)

        mig_layout.addWidget(self.mig_enabled)
        mig_layout.addWidget(QLabel("Migration Commands:"))
        mig_layout.addWidget(self.mig_cmds)

        mig_group.setLayout(mig_layout)
        form_layout.addWidget(mig_group)

        scroll.setWidget(form_container)
        layout.addWidget(scroll)

        # Action Buttons
        actions_layout = QHBoxLayout()

        save_btn = QPushButton("💾 Save Config")
        save_btn.clicked.connect(self._save_config)
        actions_layout.addWidget(save_btn)

        self.deploy_btn = QPushButton("🚀 Deploy Now")
        self.deploy_btn.clicked.connect(self.start_deployment)
        self.deploy_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        actions_layout.addWidget(self.deploy_btn)

        layout.addLayout(actions_layout)

        return widget

    def _create_log_widget(self) -> QWidget:
        """Create the deployment log widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        layout.addWidget(QLabel("Deployment Log"))

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-family: 'Courier New';")
        layout.addWidget(self.log_output)

        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.clicked.connect(lambda: self.log_output.clear())
        layout.addWidget(clear_log_btn)

        return widget

    def _browse_file(self, line_edit: QLineEdit):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            line_edit.setText(file_path)

    def _get_current_config(self) -> Dict:
        """Collect all form data into a dictionary"""
        return {
            'ec2_host': self.ec2_host.text(),
            'ec2_user': self.ec2_user.text(),
            'ec2_key_path': self.ec2_key_path.text(),
            'git_user': self.git_user.text(),
            'git_token': self.git_token.text(),
            'git_repo': self.git_repo.text(),
            'branch': self.branch.text(),
            'app_dir': self.app_dir.text(),
            'install_commands': self.install_cmds.toPlainText().split('\n'),
            'run_commands': self.run_cmds.toPlainText().split('\n'),
            'migration_enabled': self.mig_enabled.isChecked(),
            'migration_commands': self.mig_cmds.toPlainText().split('\n')
        }

    def _load_config_list(self):
        """Refresh the configuration dropdown"""
        self.config_dropdown.blockSignals(True)
        self.config_dropdown.clear()
        self.config_dropdown.addItem("-- New Configuration --")

        configs = self.config_manager.list_configs()
        for config in configs:
            self.config_dropdown.addItem(config)

        if self.current_config_name:
            index = self.config_dropdown.findText(self.current_config_name)
            if index >= 0:
                self.config_dropdown.setCurrentIndex(index)

        self.config_dropdown.blockSignals(False)

    def _on_config_selected(self, index: int):
        """Handle configuration selection from dropdown"""
        if index <= 0:
            self._clear_form()
            self.current_config_name = None
            return

        name = self.config_dropdown.currentText()
        success, config, message = self.config_manager.load_config(name)

        if success:
            self._fill_form(config)
            self.current_config_name = name
            self.statusBar().showMessage(message)
        else:
            QMessageBox.warning(self, "Error", message)

    def _save_config(self):
        """Save current form data to a configuration file"""
        name = self.current_config_name
        if not name:
            name, ok = QInputDialog.getText(self, "Save Configuration", "Enter a name for this configuration:")
            if not ok or not name:
                return
            self.current_config_name = name

        config = self._get_current_config()
        success, message = self.config_manager.save_config(name, config)

        if success:
            self._load_config_list()
            self.statusBar().showMessage(message)
        else:
            QMessageBox.warning(self, "Error", message)

    def _delete_current_config(self):
        """Delete the currently selected configuration"""
        if not self.current_config_name:
            return

        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete '{self.current_config_name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            success, message = self.config_manager.delete_config(self.current_config_name)
            if success:
                self.current_config_name = None
                self._load_config_list()
                self._clear_form()
                self.statusBar().showMessage(message)
            else:
                QMessageBox.warning(self, "Error", message)

    def _clear_form(self):
        """Reset all form fields"""
        self.ec2_host.clear()
        self.ec2_user.clear()
        self.ec2_key_path.clear()
        self.git_user.clear()
        self.git_token.clear()
        self.git_repo.clear()
        self.branch.setText("main")
        self.app_dir.clear()
        self.install_cmds.clear()
        self.run_cmds.clear()
        self.mig_enabled.setChecked(False)
        self.mig_cmds.clear()

    def _fill_form(self, config: Dict):
        """Fill form fields with configuration data"""
        self.ec2_host.setText(config.get('ec2_host', ''))
        self.ec2_user.setText(config.get('ec2_user', ''))
        self.ec2_key_path.setText(config.get('ec2_key_path', ''))
        self.git_user.setText(config.get('git_user', ''))
        self.git_token.setText(config.get('git_token', ''))
        self.git_repo.setText(config.get('git_repo', ''))
        self.branch.setText(config.get('branch', 'main'))
        self.app_dir.setText(config.get('app_dir', ''))
        self.install_cmds.setPlainText('\n'.join(config.get('install_commands', [])))
        self.run_cmds.setPlainText('\n'.join(config.get('run_commands', [])))
        self.mig_enabled.setChecked(config.get('migration_enabled', False))
        self.mig_cmds.setPlainText('\n'.join(config.get('migration_commands', [])))

    def start_deployment(self):
        """Start the deployment worker thread"""
        config = self._get_current_config()

        # Basic validation
        if not all([config['ec2_host'], config['ec2_user'], config['ec2_key_path']]):
            QMessageBox.warning(self, "Missing Info", "Please fill in EC2 connection details")
            return

        if not all([config['git_user'], config['git_token'], config['git_repo']]):
            QMessageBox.warning(self, "Missing Info", "Please fill in Git repository details")
            return

        self.deploy_btn.setEnabled(False)
        self.log_output.append("\n" + "=" * 50 + "\n")

        self.worker = DeploymentWorker(config)
        self.worker.log_signal.connect(self.log_output.append)
        self.worker.progress_signal.connect(self.progress_bar.setValue)
        self.worker.finished_signal.connect(self.on_deployment_finished)
        self.worker.start()

    def on_deployment_finished(self, success: bool, message: str):
        """Handle deployment completion"""
        self.deploy_btn.setEnabled(True)
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Error", message)


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("QuickDeploy (Remote management, CI-CD)")
    app.setApplicationVersion("0.9")
    app.setOrganizationName("liotauhid@gmail.com")

    window = DeploymentApp()
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
