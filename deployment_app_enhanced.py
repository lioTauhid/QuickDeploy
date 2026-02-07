import json
import os
import sys
import re
from typing import Dict, List, Optional
from pathlib import Path
from paramiko import SSHClient, AutoAddPolicy, SFTPClient
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QTextCursor, QKeyEvent
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QTextEdit, QPushButton,
    QFileDialog, QMessageBox, QProgressBar, QGroupBox,
    QScrollArea, QSplitter, QCheckBox, QTabWidget, QTreeWidget,
    QTreeWidgetItem, QTableWidget, QTableWidgetItem, QHeaderView,
    QInputDialog, QMenu, QComboBox
)
from PyQt6.QtCore import QPoint
from PyQt6.QtGui import QTextOption


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
                term='dumb',  # Use 'dumb' terminal to avoid ANSI escape codes
                width=120,
                height=40
            )
            # Disable colored output and special sequences
            self.shell_channel.send('export TERM=dumb\n')
            self.shell_channel.send('unset LS_COLORS\n')
            # Source bash profile and aliases
            self.shell_channel.send('source ~/.bashrc 2>/dev/null; source ~/.bash_aliases 2>/dev/null\n')

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


class AnsiEscapeFilter:
    """Filter to remove ANSI escape sequences and control characters"""

    # ANSI escape sequence pattern
    ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[=>]|\[\?[0-9]+[hl]')

    # Bracketed paste mode sequences
    BRACKETED_PASTE = re.compile(r'\[\?2004[hl]')

    @staticmethod
    def strip_ansi(text: str) -> str:
        """Remove ANSI escape sequences from text"""
        # Remove ANSI color codes and cursor movements
        text = AnsiEscapeFilter.ANSI_ESCAPE_PATTERN.sub('', text)

        # Remove bracketed paste mode sequences
        text = AnsiEscapeFilter.BRACKETED_PASTE.sub('', text)

        # Remove other control sequences
        text = re.sub(r'\x1b\[[0-9;]*m', '', text)  # Color codes
        text = re.sub(r'\x1b\[[0-9]*[ABCDEFGJKST]', '', text)  # Cursor movements
        text = re.sub(r'\x1b\[\?[0-9]+[hl]', '', text)  # Private mode settings

        # Remove carriage returns but keep newlines
        text = text.replace('\r\n', '\n').replace('\r', '')

        return text


class TerminalWidget(QTextEdit):
    """Custom terminal widget that acts like a real terminal"""
    command_entered = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setFont(QFont("Courier", 10))
        self.setStyleSheet("background-color: #1e1e1e; color: #00ff00;")
        self.command_buffer = ""
        self.command_history = []
        self.history_index = -1
        self.prompt = "$ "
        self.current_line_start = 0

        # Set word wrap mode
        self.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        self.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

    def append_output(self, text: str, color: str = "#ffffff"):
        """Append output text"""
        # Strip ANSI escape sequences
        text = AnsiEscapeFilter.strip_ansi(text)

        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.setTextCursor(cursor)

        # Insert text with color
        escaped_text = text.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
        self.insertHtml(f'<span style="color: {color};">{escaped_text}</span>')
        self.ensureCursorVisible()

        # Update current line start position
        self.current_line_start = self.textCursor().position()

    def show_prompt(self):
        """Show command prompt"""
        self.append_output(self.prompt, "#00ff00")
        self.current_line_start = self.textCursor().position()

    def keyPressEvent(self, event: QKeyEvent):
        """Handle key press events"""
        cursor = self.textCursor()

        # Prevent editing before the current line start
        if cursor.position() < self.current_line_start:
            if event.key() in [Qt.Key.Key_Left, Qt.Key.Key_Backspace, Qt.Key.Key_Up, Qt.Key.Key_Down]:
                return
            cursor.setPosition(self.current_line_start)
            self.setTextCursor(cursor)

        # Handle Enter key
        if event.key() in [Qt.Key.Key_Return, Qt.Key.Key_Enter]:
            # Get the command from current line
            cursor.setPosition(self.current_line_start)
            cursor.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
            command = cursor.selectedText().strip()

            # Move to end and add newline
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(cursor)
            self.insertPlainText("\n")

            # Save to history
            if command:
                self.command_history.append(command)
                self.history_index = len(self.command_history)
                self.command_entered.emit(command)
            else:
                self.show_prompt()

            return

        # Handle Up arrow - command history
        elif event.key() == Qt.Key.Key_Up:
            if self.command_history and self.history_index > 0:
                self.history_index -= 1
                self._replace_current_command(self.command_history[self.history_index])
            return

        # Handle Down arrow - command history
        elif event.key() == Qt.Key.Key_Down:
            if self.command_history:
                if self.history_index < len(self.command_history) - 1:
                    self.history_index += 1
                    self._replace_current_command(self.command_history[self.history_index])
                else:
                    self.history_index = len(self.command_history)
                    self._replace_current_command("")
            return

        # Handle Backspace
        elif event.key() == Qt.Key.Key_Backspace:
            if cursor.position() <= self.current_line_start:
                return

        # Handle Left arrow
        elif event.key() == Qt.Key.Key_Left:
            if cursor.position() <= self.current_line_start:
                return

        # Handle Home key
        elif event.key() == Qt.Key.Key_Home:
            cursor.setPosition(self.current_line_start)
            self.setTextCursor(cursor)
            return

        # Default behavior for other keys
        super().keyPressEvent(event)

    def _replace_current_command(self, command: str):
        """Replace the current command line with new text"""
        cursor = self.textCursor()
        cursor.setPosition(self.current_line_start)
        cursor.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
        cursor.removeSelectedText()
        cursor.insertText(command)
        self.setTextCursor(cursor)


class TerminalWorker(QThread):
    """Worker thread for interactive shell terminal"""
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    prompt_signal = pyqtSignal()

    def __init__(self, ssh_manager: SSHConnectionManager, command: str):
        super().__init__()
        self.ssh_manager = ssh_manager
        self.command = command
        self.running = True

    def run(self):
        try:
            channel = self.ssh_manager.get_shell_channel()
            if not channel:
                self.error_signal.emit("Not connected to server")
                self.prompt_signal.emit()
                return

            # Send command
            channel.send(self.command + '\n')

            # Read output with timeout
            output = ""
            import time
            start_time = time.time()
            timeout = 30  # 30 seconds timeout

            while self.running and (time.time() - start_time) < timeout:
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                    if chunk:
                        output += chunk
                        # Emit chunks as they arrive for real-time display
                        self.output_signal.emit(chunk)
                        start_time = time.time()  # Reset timeout on activity
                else:
                    time.sleep(0.1)

                # Check if command completed (simple heuristic)
                if output.strip().endswith('$') or output.strip().endswith('#'):
                    break

            self.prompt_signal.emit()

        except Exception as e:
            self.error_signal.emit(f"Command failed: {str(e)}")
            self.prompt_signal.emit()

    def stop(self):
        self.running = False


class FileOperationWorker(QThread):
    """Worker thread for file operations"""
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
        except Exception as e:
            self.finished_signal.emit(False, str(e))

    def _list_directory(self):
        path = self.kwargs.get('path', '.')
        success, output, error = self.ssh_manager.execute_command(f"ls -la {path}")
        if success:
            self.finished_signal.emit(True, output)
        else:
            self.finished_signal.emit(False, error)

    def _upload_file(self):
        local_path = self.kwargs['local_path']
        remote_path = self.kwargs['remote_path']

        if not self.ssh_manager.sftp_client:
            self.finished_signal.emit(False, "SFTP not available")
            return

        file_size = os.path.getsize(local_path)
        uploaded = 0

        def callback(transferred, total):
            progress = int((transferred / total) * 100)
            self.progress_signal.emit(progress)

        self.ssh_manager.sftp_client.put(local_path, remote_path, callback=callback)
        self.finished_signal.emit(True, f"Uploaded {local_path} to {remote_path}")

    def _download_file(self):
        remote_path = self.kwargs['remote_path']
        local_path = self.kwargs['local_path']

        if not self.ssh_manager.sftp_client:
            self.finished_signal.emit(False, "SFTP not available")
            return

        def callback(transferred, total):
            progress = int((transferred / total) * 100)
            self.progress_signal.emit(progress)

        self.ssh_manager.sftp_client.get(remote_path, local_path, callback=callback)
        self.finished_signal.emit(True, f"Downloaded {remote_path} to {local_path}")

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


class TerminalTab(QWidget):
    """Interactive SSH terminal tab with integrated terminal interface"""

    def __init__(self, ssh_manager: SSHConnectionManager):
        super().__init__()
        self.ssh_manager = ssh_manager
        self.worker = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Terminal widget
        self.terminal = TerminalWidget()
        self.terminal.command_entered.connect(self.execute_command)
        layout.addWidget(self.terminal)

        # Control buttons
        button_layout = QHBoxLayout()

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_terminal)
        button_layout.addWidget(clear_btn)

        button_layout.addStretch()

        layout.addLayout(button_layout)

        # Welcome message
        self.terminal.append_output("=== SSH Terminal ===\n", "#00aaff")
        self.terminal.append_output("Connect to server first before executing commands\n", "#ffaa00")
        self.terminal.append_output("Type your commands below. Use Up/Down arrows for history.\n\n", "#aaaaaa")
        self.terminal.show_prompt()

    def execute_command(self, command: str):
        if not self.ssh_manager.is_connected:
            self.terminal.append_output("Error: Not connected to server\n", "#ff0000")
            self.terminal.show_prompt()
            return

        # Handle special commands
        if command.lower() in ['clear', 'cls']:
            self.clear_terminal()
            return

        self.worker = TerminalWorker(self.ssh_manager, command)
        self.worker.output_signal.connect(self.append_output)
        self.worker.error_signal.connect(self.append_error)
        self.worker.prompt_signal.connect(self.show_prompt)
        self.worker.start()

    def append_output(self, text: str):
        # Filter out the echoed command and extra prompts
        lines = text.split('\n')
        filtered_lines = []

        for line in lines:
            # Skip lines that are just prompts
            if line.strip() in ['$', '#', '$ ', '# ']:
                continue
            filtered_lines.append(line)

        if filtered_lines:
            output = '\n'.join(filtered_lines)
            if output.strip():
                self.terminal.append_output(output, "#ffffff")

    def append_error(self, text: str):
        self.terminal.append_output(text + "\n", "#ff0000")

    def show_prompt(self):
        self.terminal.show_prompt()

    def clear_terminal(self):
        self.terminal.clear()
        self.terminal.append_output("=== SSH Terminal ===\n", "#00aaff")
        self.terminal.show_prompt()


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

        # Get parent directory
        parent_path = os.path.dirname(self.current_path)
        if not parent_path:
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

        rename_action = menu.addAction("✏️ Rename")
        rename_action.triggered.connect(lambda: self.rename_file(filename))

        delete_action = menu.addAction("🗑️ Delete")
        delete_action.triggered.connect(lambda: self.delete_file(filename))

        menu.exec(self.file_table.viewport().mapToGlobal(position))


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
        self.setWindowTitle("Server Deployment Tool - Enhanced")
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
        self.terminal_tab = TerminalTab(self.ssh_manager)
        self.tabs.addTab(self.terminal_tab, "💻 Terminal")

        # File browser tab
        self.file_browser_tab = FileBrowserTab(self.ssh_manager)
        self.tabs.addTab(self.file_browser_tab, "📁 File Browser")

        main_layout.addWidget(self.tabs)

        self.statusBar().showMessage(f"Ready - Config directory: {self.config_manager.get_config_path()}")

    def _create_connection_toolbar(self) -> QHBoxLayout:
        """Create connection status toolbar"""
        layout = QHBoxLayout()

        self.connection_status = QLabel("● Disconnected")
        self.connection_status.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(self.connection_status)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.toggle_connection)
        layout.addWidget(self.connect_btn)

        layout.addStretch()

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

        scroll = QScrollArea()
        form_widget = QWidget()
        form_layout = QGridLayout(form_widget)

        # EC2 Configuration
        ec2_group = QGroupBox("EC2 Server Configuration")
        ec2_layout = QGridLayout(ec2_group)

        self.ec2_user_input = QLineEdit()
        self.ec2_host_input = QLineEdit()
        self.ec2_key_input = QLineEdit()

        ec2_layout.addWidget(QLabel("EC2 User:"), 0, 0)
        ec2_layout.addWidget(self.ec2_user_input, 0, 1)
        ec2_layout.addWidget(QLabel("EC2 Host:"), 1, 0)
        ec2_layout.addWidget(self.ec2_host_input, 1, 1)
        ec2_layout.addWidget(QLabel("SSH Key Path:"), 2, 0)

        key_layout = QHBoxLayout()
        key_layout.addWidget(self.ec2_key_input)
        key_browse_btn = QPushButton("Browse")
        key_browse_btn.clicked.connect(self._browse_ssh_key)
        key_layout.addWidget(key_browse_btn)
        ec2_layout.addLayout(key_layout, 2, 1)

        form_layout.addWidget(ec2_group, 0, 0, 1, 2)

        # Git Configuration
        git_group = QGroupBox("Git Repository Configuration")
        git_layout = QGridLayout(git_group)

        self.app_dir_input = QLineEdit()
        self.git_user_input = QLineEdit()
        self.git_token_input = QLineEdit()
        self.git_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.git_repo_input = QLineEdit()
        self.git_repo_input.setPlaceholderText("github.com/user/repo.git")
        self.branch_input = QLineEdit()

        git_layout.addWidget(QLabel("App Directory:"), 0, 0)
        git_layout.addWidget(self.app_dir_input, 0, 1)
        git_layout.addWidget(QLabel("Git User:"), 1, 0)
        git_layout.addWidget(self.git_user_input, 1, 1)
        git_layout.addWidget(QLabel("Git Token:"), 2, 0)
        git_layout.addWidget(self.git_token_input, 2, 1)
        git_layout.addWidget(QLabel("Git Repository:"), 3, 0)
        git_layout.addWidget(self.git_repo_input, 3, 1)
        git_layout.addWidget(QLabel("Branch:"), 4, 0)
        git_layout.addWidget(self.branch_input, 4, 1)

        form_layout.addWidget(git_group, 1, 0, 1, 2)

        # Commands Configuration
        cmd_group = QGroupBox("Commands Configuration")
        cmd_layout = QVBoxLayout(cmd_group)

        cmd_layout.addWidget(QLabel("Install Commands (one per line):"))
        self.install_commands_input = QTextEdit()
        self.install_commands_input.setMaximumHeight(80)
        cmd_layout.addWidget(self.install_commands_input)

        migration_layout = QVBoxLayout()
        self.migration_enabled_checkbox = QCheckBox("Enable Migration Commands")
        self.migration_enabled_checkbox.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        self.migration_enabled_checkbox.stateChanged.connect(self._on_migration_checkbox_changed)
        migration_layout.addWidget(self.migration_enabled_checkbox)

        migration_label = QLabel("Migration Commands (one per line):")
        migration_label.setStyleSheet("color: #666;")
        migration_layout.addWidget(migration_label)

        self.migration_commands_input = QTextEdit()
        self.migration_commands_input.setMaximumHeight(80)
        self.migration_commands_input.setEnabled(False)
        self.migration_commands_input.setPlaceholderText("e.g., python3 manage.py migrate")
        migration_layout.addWidget(self.migration_commands_input)

        cmd_layout.addLayout(migration_layout)

        cmd_layout.addWidget(QLabel("Run Commands (one per line):"))
        self.run_commands_input = QTextEdit()
        self.run_commands_input.setMaximumHeight(80)
        cmd_layout.addWidget(self.run_commands_input)

        form_layout.addWidget(cmd_group, 2, 0, 1, 2)

        scroll.setWidget(form_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)

        # Buttons
        button_layout = QHBoxLayout()

        save_btn = QPushButton("💾 Save Config")
        save_btn.clicked.connect(self._save_config)
        button_layout.addWidget(save_btn)

        save_as_btn = QPushButton("💾 Save As...")
        save_as_btn.clicked.connect(self._save_config_as)
        button_layout.addWidget(save_as_btn)

        deploy_btn = QPushButton("🚀 Deploy")
        deploy_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        deploy_btn.clicked.connect(self._start_deployment)
        button_layout.addWidget(deploy_btn)

        layout.addLayout(button_layout)

        return widget

    def _create_log_widget(self) -> QWidget:
        """Create the deployment log widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        title = QLabel("Deployment Log")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(QFont("Courier", 10))
        layout.addWidget(self.log_output)

        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        return widget

    def _load_config_list(self):
        """Load list of saved configurations into dropdown"""
        self.config_dropdown.blockSignals(True)

        current_text = self.config_dropdown.currentText()
        self.config_dropdown.clear()
        self.config_dropdown.addItem("-- New Configuration --")

        configs = self.config_manager.list_configs()
        for config_name in configs:
            self.config_dropdown.addItem(config_name)

        index = self.config_dropdown.findText(current_text)
        if index >= 0:
            self.config_dropdown.setCurrentIndex(index)

        self.config_dropdown.blockSignals(False)

    def _on_config_selected(self, index):
        """Handle configuration selection from dropdown"""
        if index == 0:
            self.current_config_name = None
            self._clear_form()
            return

        config_name = self.config_dropdown.currentText()
        success, config, message = self.config_manager.load_config(config_name)

        if success:
            self._populate_form(config)
            self.current_config_name = config_name
            self.statusBar().showMessage(message)
        else:
            QMessageBox.critical(self, "Error", message)

    def _clear_form(self):
        """Clear all form fields"""
        self.ec2_user_input.clear()
        self.ec2_host_input.clear()
        self.ec2_key_input.clear()
        self.app_dir_input.clear()
        self.git_user_input.clear()
        self.git_token_input.clear()
        self.git_repo_input.clear()
        self.branch_input.clear()
        self.install_commands_input.clear()
        self.migration_enabled_checkbox.setChecked(False)
        self.migration_commands_input.clear()
        self.run_commands_input.clear()

    def _populate_form(self, config: Dict):
        """Populate form fields with configuration data"""
        self.ec2_user_input.setText(config.get('ec2_user', ''))
        self.ec2_host_input.setText(config.get('ec2_host', ''))
        self.ec2_key_input.setText(config.get('ec2_key_path', ''))
        self.app_dir_input.setText(config.get('app_dir', ''))
        self.git_user_input.setText(config.get('git_user', ''))
        self.git_token_input.setText(config.get('git_token', ''))
        self.git_repo_input.setText(config.get('git_repo', ''))
        self.branch_input.setText(config.get('branch', ''))

        install_commands = '\n'.join(config.get('install_commands', []))
        self.install_commands_input.setPlainText(install_commands)

        migration_enabled = config.get('migration_enabled', False)
        self.migration_enabled_checkbox.setChecked(migration_enabled)
        migration_commands = '\n'.join(config.get('migration_commands', []))
        self.migration_commands_input.setPlainText(migration_commands)

        run_commands = '\n'.join(config.get('run_commands', []))
        self.run_commands_input.setPlainText(run_commands)

    def _save_config(self):
        """Save configuration (update existing or prompt for name if new)"""
        if self.current_config_name:
            config = self._get_current_config()
            success, message = self.config_manager.save_config(self.current_config_name, config)

            if success:
                self.statusBar().showMessage(message)
                self._load_config_list()
            else:
                QMessageBox.critical(self, "Error", message)
        else:
            self._save_config_as()

    def _save_config_as(self):
        """Save configuration with a new name"""
        config_name, ok = QInputDialog.getText(
            self, "Save Configuration",
            "Enter configuration name:"
        )

        if ok and config_name:
            config = self._get_current_config()
            success, message = self.config_manager.save_config(config_name, config)

            if success:
                self.current_config_name = config_name
                self.statusBar().showMessage(message)
                self._load_config_list()

                index = self.config_dropdown.findText(config_name)
                if index >= 0:
                    self.config_dropdown.setCurrentIndex(index)
            else:
                QMessageBox.critical(self, "Error", message)

    def _delete_current_config(self):
        """Delete the currently selected configuration"""
        if not self.current_config_name:
            QMessageBox.information(self, "No Config", "No configuration selected to delete")
            return

        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete configuration '{self.current_config_name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            success, message = self.config_manager.delete_config(self.current_config_name)

            if success:
                self.statusBar().showMessage(message)
                self.current_config_name = None
                self._load_config_list()
                self.config_dropdown.setCurrentIndex(0)
                self._clear_form()
            else:
                QMessageBox.critical(self, "Error", message)

    def _on_migration_checkbox_changed(self, state):
        """Handle migration checkbox state change"""
        enabled = state == Qt.CheckState.Checked.value
        self.migration_commands_input.setEnabled(enabled)
        if enabled:
            self.migration_commands_input.setStyleSheet("")
        else:
            self.migration_commands_input.setStyleSheet("background-color: #f0f0f0;")

    def _browse_ssh_key(self):
        """Browse for SSH key file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select SSH Key File", os.path.expanduser("~"), "PEM files (*.pem);;All files (*)"
        )
        if file_path:
            self.ec2_key_input.setText(file_path)

    def _get_current_config(self) -> Dict:
        """Get current configuration from form fields"""
        install_commands = [
            cmd.strip() for cmd in self.install_commands_input.toPlainText().split('\n')
            if cmd.strip()
        ]

        migration_commands = [
            cmd.strip() for cmd in self.migration_commands_input.toPlainText().split('\n')
            if cmd.strip()
        ]

        run_commands = [
            cmd.strip() for cmd in self.run_commands_input.toPlainText().split('\n')
            if cmd.strip()
        ]

        git_repo = self.git_repo_input.text()
        git_repo = git_repo.replace('https://', '').replace('http://', '')

        return {
            'ec2_user': self.ec2_user_input.text(),
            'ec2_host': self.ec2_host_input.text(),
            'ec2_key_path': self.ec2_key_input.text(),
            'app_dir': self.app_dir_input.text(),
            'git_user': self.git_user_input.text(),
            'git_token': self.git_token_input.text(),
            'git_repo': git_repo,
            'branch': self.branch_input.text(),
            'install_commands': install_commands,
            'migration_enabled': self.migration_enabled_checkbox.isChecked(),
            'migration_commands': migration_commands,
            'run_commands': run_commands
        }

    def _start_deployment(self):
        """Start the deployment process"""
        config = self._get_current_config()
        required_fields = ['ec2_user', 'ec2_host', 'ec2_key_path', 'app_dir', 'git_repo', 'branch']
        missing_fields = [field for field in required_fields if not config.get(field)]

        if missing_fields:
            QMessageBox.warning(
                self, "Missing Configuration",
                f"Please fill in the following required fields: {', '.join(missing_fields)}"
            )
            return

        if config.get('migration_enabled', False) and not config.get('migration_commands'):
            reply = QMessageBox.question(
                self, "Migration Commands",
                "Migration is enabled but no migration commands are specified. Continue anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return

        self.log_output.clear()
        self.progress_bar.setValue(0)

        self.worker = DeploymentWorker(config)
        self.worker.log_signal.connect(self._append_log)
        self.worker.progress_signal.connect(self.progress_bar.setValue)
        self.worker.finished_signal.connect(self._deployment_finished)
        self.worker.start()

        migration_status = "with migrations" if config.get('migration_enabled', False) else "without migrations"
        self.statusBar().showMessage(f"Deployment in progress {migration_status}...")

    def _append_log(self, message: str):
        """Append message to log output"""
        self.log_output.append(message)
        cursor = self.log_output.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_output.setTextCursor(cursor)

    def _deployment_finished(self, success: bool, message: str):
        """Handle deployment completion"""
        if success:
            self.statusBar().showMessage("Deployment completed successfully!")
            QMessageBox.information(self, "Success", message)
        else:
            self.statusBar().showMessage("Deployment failed!")
            QMessageBox.critical(self, "Error", message)
        self.worker = None

    def closeEvent(self, event):
        """Handle application close"""
        self.ssh_manager.disconnect()
        event.accept()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Server Deployment Tool - Enhanced")
    app.setApplicationVersion("2.3")
    app.setOrganizationName("Deployment Tools")

    window = DeploymentApp()
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
