import sys
import os
import time
import threading
import stat
import subprocess
import platform
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QTableWidget, QTableWidgetItem,
                             QHeaderView, QFileDialog, QMessageBox, QInputDialog,
                             QPlainTextEdit, QMenu, QTabWidget, QDialog, QDialogButtonBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QTextCursor, QColor
import paramiko


class SSHConnection:
    def __init__(self):
        self.client = None
        self.shell = None
        self.sftp = None

    def connect(self, hostname, username, password=None, key_path=None):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if key_path:
                self.client.connect(hostname, username=username, key_filename=key_path, timeout=10)
            else:
                self.client.connect(hostname, username=username, password=password, timeout=10)
            self.shell = self.client.invoke_shell(term='xterm', width=120, height=40)
            self.sftp = self.client.open_sftp()
            return True, "Connected"
        except Exception as e:
            return False, str(e)


class TerminalThread(QThread):
    output_received = pyqtSignal(str)

    def __init__(self, shell):
        super().__init__()
        self.shell = shell
        self.running = True

    def run(self):
        while self.running:
            if self.shell.recv_ready():
                try:
                    data = self.shell.recv(4096).decode('utf-8', errors='ignore')
                    if data:
                        self.output_received.emit(data)
                except Exception as e:
                    print(f"Error reading from shell: {e}")
                    break
            else:
                time.sleep(0.01)

    def stop(self):
        self.running = False


class FileEditDialog(QDialog):
    def __init__(self, parent, sftp, filepath):
        super().__init__(parent)
        self.sftp = sftp
        self.filepath = filepath
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(f"Editing: {os.path.basename(self.filepath)}")
        self.resize(800, 600)
        self.layout = QVBoxLayout(self)

        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Courier New", 10))
        self.layout.addWidget(self.text_edit)

        try:
            with self.sftp.open(self.filepath, 'r') as f:
                self.text_edit.setPlainText(f.read().decode('utf-8', errors='ignore'))
        except Exception as e:
            self.text_edit.setPlainText(f"Error reading file: {e}")

        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.save_file)
        self.layout.addWidget(self.save_btn)

    def save_file(self):
        try:
            content = self.text_edit.toPlainText()
            with self.sftp.open(self.filepath, 'w') as f:
                f.write(content)
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not save file: {e}")


class NativeTerminalLauncher:
    """Cross-platform native terminal launcher for SSH connections"""

    @staticmethod
    def open_native_terminal(hostname, username, password=None):
        """
        Open a native terminal and connect to remote instance via SSH.
        Supports Windows, macOS, and Linux.
        
        Args:
            hostname: Remote host address
            username: SSH username
            password: SSH password (optional, will prompt if not provided)
        """
        system = platform.system()

        try:
            if system == "Windows":
                NativeTerminalLauncher._open_windows_terminal(hostname, username, password)
            elif system == "Darwin":  # macOS
                NativeTerminalLauncher._open_macos_terminal(hostname, username, password)
            elif system == "Linux":
                NativeTerminalLauncher._open_linux_terminal(hostname, username, password)
            else:
                raise Exception(f"Unsupported operating system: {system}")
        except Exception as e:
            raise Exception(f"Failed to open native terminal: {e}")

    @staticmethod
    def _open_windows_terminal(hostname, username, password=None):
        """Open Windows Command Prompt with SSH connection"""
        if password:
            # Using SSH with password (note: this is less secure, better to use key-based auth)
            ssh_cmd = f'ssh {username}@{hostname}'
        else:
            ssh_cmd = f'ssh {username}@{hostname}'

        # Open Command Prompt and execute SSH command
        subprocess.Popen(f'start cmd /k {ssh_cmd}', shell=True)

    @staticmethod
    def _open_macos_terminal(hostname, username, password=None):
        """Open macOS Terminal with SSH connection"""
        ssh_cmd = f'ssh {username}@{hostname}'

        # Use osascript to open Terminal.app and run SSH command
        applescript = f'''
        tell application "Terminal"
            activate
            do script "{ssh_cmd}"
        end tell
        '''

        subprocess.Popen(['osascript', '-e', applescript])

    @staticmethod
    def _open_linux_terminal(hostname, username, password=None):
        """Open Linux terminal with SSH connection"""
        ssh_cmd = f'ssh {username}@{hostname}'

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


class DeploymentApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ssh = SSHConnection()
        self.terminal_thread = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle('QuickDeploy - Remote Management')
        self.setGeometry(100, 100, 1200, 700)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Connection Panel
        conn_panel = QHBoxLayout()
        self.host_input = QLineEdit('localhost')
        self.user_input = QLineEdit('ubuntu')
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.connect_btn = QPushButton('Connect')
        self.connect_btn.clicked.connect(self.connect_ssh)

        # New button for native terminal
        self.native_term_btn = QPushButton('🖥️ Native Terminal')
        self.native_term_btn.clicked.connect(self.open_native_terminal)
        self.native_term_btn.setToolTip('Open system native terminal with SSH connection')

        conn_panel.addWidget(QLabel('Host:'))
        conn_panel.addWidget(self.host_input)
        conn_panel.addWidget(QLabel('User:'))
        conn_panel.addWidget(self.user_input)
        conn_panel.addWidget(QLabel('Pass:'))
        conn_panel.addWidget(self.pass_input)
        conn_panel.addWidget(self.connect_btn)
        conn_panel.addWidget(self.native_term_btn)
        layout.addLayout(conn_panel)

        # Terminal and File Browser
        self.tabs = QTabWidget()
        self.terminal_tab = QWidget()
        self.file_tab = QWidget()
        self.tabs.addTab(self.terminal_tab, "Terminal")
        self.tabs.addTab(self.file_tab, "File Browser")
        layout.addWidget(self.tabs)

        # Terminal UI
        self.term_layout = QVBoxLayout(self.terminal_tab)
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setStyleSheet("background-color: black; color: white; font-family: 'Courier New';")
        self.term_input = QLineEdit()
        self.term_input.returnPressed.connect(self.send_command)
        self.term_layout.addWidget(self.terminal_output)
        self.term_layout.addWidget(self.term_input)

        # File Browser UI
        self.file_layout = QVBoxLayout(self.file_tab)
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(4)
        self.file_table.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Date'])
        self.file_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.file_layout.addWidget(self.file_table)

        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton('Refresh')
        self.refresh_btn.clicked.connect(self.refresh_files)
        self.rename_btn = QPushButton('Rename')
        self.rename_btn.clicked.connect(self.rename_file)
        self.edit_btn = QPushButton('Edit')
        self.edit_btn.clicked.connect(self.edit_file)
        btn_layout.addWidget(self.refresh_btn)
        btn_layout.addWidget(self.rename_btn)
        btn_layout.addWidget(self.edit_btn)
        self.file_layout.addLayout(btn_layout)

    def connect_ssh(self):
        host = self.host_input.text()
        user = self.user_input.text()
        password = self.pass_input.text()
        success, msg = self.ssh.connect(host, user, password)
        if success:
            if self.terminal_thread:
                self.terminal_thread.stop()
            self.terminal_thread = TerminalThread(self.ssh.shell)
            self.terminal_thread.output_received.connect(self.update_terminal)
            self.terminal_thread.start()
            QMessageBox.information(self, 'Success', 'Connected to ' + host)
            self.refresh_files()
        else:
            QMessageBox.critical(self, 'Error', msg)

    def open_native_terminal(self):
        """Open native terminal with SSH connection"""
        host = self.host_input.text()
        user = self.user_input.text()
        password = self.pass_input.text()

        if not host or not user:
            QMessageBox.warning(self, 'Warning', 'Please enter host and username.')
            return

        try:
            # Note: For security, we don't pass password to the terminal launcher
            # The user will be prompted for password by SSH
            NativeTerminalLauncher.open_native_terminal(host, user, None)
            QMessageBox.information(self, 'Success', f'Opening native terminal for {user}@{host}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

    def update_terminal(self, text):
        self.terminal_output.insertPlainText(text)
        self.terminal_output.ensureCursorVisible()

    def send_command(self):
        cmd = self.term_input.text() + '\n'
        self.ssh.shell.send(cmd)
        self.term_input.clear()

    def refresh_files(self):
        if not self.ssh.sftp: return
        try:
            files = self.ssh.sftp.listdir_attr('.')
            self.file_table.setRowCount(0)
            for file in files:
                row = self.file_table.rowCount()
                self.file_table.insertRow(row)
                self.file_table.setItem(row, 0, QTableWidgetItem(file.filename))
                self.file_table.setItem(row, 1, QTableWidgetItem(str(file.st_size)))
                self.file_table.setItem(row, 2, QTableWidgetItem('Dir' if stat.S_ISDIR(file.st_mode) else 'File'))
                self.file_table.setItem(row, 3, QTableWidgetItem(time.ctime(file.st_mtime)))
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

    def rename_file(self):
        selected = self.file_table.currentRow()
        if selected < 0: return
        old_name = self.file_table.item(selected, 0).text()
        new_name, ok = QInputDialog.getText(self, 'Rename', 'Enter new name:', text=old_name)
        if ok and new_name:
            try:
                self.ssh.sftp.rename(old_name, new_name)
                self.refresh_files()
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))

    def edit_file(self):
        selected = self.file_table.currentRow()
        if selected < 0: return
        filename = self.file_table.item(selected, 0).text()
        if self.file_table.item(selected, 2).text() == 'Dir':
            QMessageBox.warning(self, 'Warning', 'Cannot edit a directory.')
            return
        dialog = FileEditDialog(self, self.ssh.sftp, filename)
        if dialog.exec():
            self.refresh_files()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = DeploymentApp()
    ex.show()
    sys.exit(app.exec())
