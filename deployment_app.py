import json
import os
import sys
from typing import Dict, List
from paramiko import SSHClient, AutoAddPolicy
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QTextEdit, QPushButton,
    QFileDialog, QMessageBox, QProgressBar, QGroupBox,
    QScrollArea, QSplitter, QCheckBox
)


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

            # Create SSH client
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(AutoAddPolicy())

            # Connect to EC2 instance
            self.log_signal.emit(f"📡 Connecting to {self.config['ec2_host']}...")

            # Handle key path
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

            # Prepare deployment commands
            commands = self._prepare_commands()

            # Execute commands
            for i, command in enumerate(commands):
                self.log_signal.emit(f"📋 Executing: {command[:50]}...")

                stdin, stdout, stderr = ssh.exec_command(command)

                # Read output in real-time
                while True:
                    line = stdout.readline()
                    if not line:
                        break
                    self.log_signal.emit(line.strip())

                # Check for errors
                error_output = stderr.read().decode()
                if error_output:
                    self.log_signal.emit(f"⚠️ Warning: {error_output}")

                # Update progress
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

        # Add install commands
        if self.config.get('install_commands'):
            commands.append("echo '📦 Installing dependencies...'")
            for cmd in self.config['install_commands']:
                if cmd.strip():
                    commands.append(f"cd {app_dir} && {cmd}")

        # Add migration commands (if enabled)
        if self.config.get('migration_enabled', False) and self.config.get('migration_commands'):
            commands.append("echo '🔄 Running migrations...'")
            for cmd in self.config['migration_commands']:
                if cmd.strip():
                    commands.append(f"cd {app_dir} && {cmd}")

        # Add run commands
        if self.config.get('run_commands'):
            commands.append("echo '🚀 Starting application...'")
            for cmd in self.config['run_commands']:
                if cmd.strip():
                    commands.append(cmd)

        return commands


class DeploymentApp(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.config = {}
        self.worker = None
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Server Deployment Tool")
        self.setGeometry(100, 100, 1200, 900)

        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Create splitter for resizable panes
        splitter = QSplitter(Qt.Orientation.Horizontal)
        central_widget_layout = QVBoxLayout(central_widget)
        central_widget_layout.addWidget(splitter)

        # Left pane - Configuration
        config_widget = self._create_config_widget()
        splitter.addWidget(config_widget)

        # Right pane - Deployment log
        log_widget = self._create_log_widget()
        splitter.addWidget(log_widget)

        # Set splitter proportions
        splitter.setSizes([600, 600])

        # Status bar
        self.statusBar().showMessage("Ready")

    def _create_config_widget(self) -> QWidget:
        """Create the configuration input widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Title
        title = QLabel("Deployment Configuration")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # Configuration form
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

        # Install Commands
        cmd_layout.addWidget(QLabel("Install Commands (one per line):"))
        self.install_commands_input = QTextEdit()
        self.install_commands_input.setMaximumHeight(80)
        cmd_layout.addWidget(self.install_commands_input)

        # Migration Commands Section
        migration_layout = QVBoxLayout()

        # Migration checkbox
        self.migration_enabled_checkbox = QCheckBox("Enable Migration Commands")
        self.migration_enabled_checkbox.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        self.migration_enabled_checkbox.stateChanged.connect(self._on_migration_checkbox_changed)
        migration_layout.addWidget(self.migration_enabled_checkbox)

        # Migration commands text area
        migration_label = QLabel("Migration Commands (one per line):")
        migration_label.setStyleSheet("color: #666;")
        migration_layout.addWidget(migration_label)

        self.migration_commands_input = QTextEdit()
        self.migration_commands_input.setMaximumHeight(80)
        self.migration_commands_input.setEnabled(False)  # Initially disabled
        self.migration_commands_input.setPlaceholderText(
            "e.g., python3 manage.py migrate")
        migration_layout.addWidget(self.migration_commands_input)

        cmd_layout.addLayout(migration_layout)

        # Run Commands
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

        load_btn = QPushButton("Load Config")
        load_btn.clicked.connect(self._load_config)
        button_layout.addWidget(load_btn)

        save_btn = QPushButton("Save Config")
        save_btn.clicked.connect(self._save_config)
        button_layout.addWidget(save_btn)

        deploy_btn = QPushButton("Deploy")
        deploy_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        deploy_btn.clicked.connect(self._start_deployment)
        button_layout.addWidget(deploy_btn)

        layout.addLayout(button_layout)

        return widget

    def _create_log_widget(self) -> QWidget:
        """Create the deployment log widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Title
        title = QLabel("Deployment Log")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(QFont("Courier", 10))
        layout.addWidget(self.log_output)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        return widget

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

    def _load_config(self):
        """Load configuration from JSON file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", "", "JSON files (*.json);;All files (*)"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'r') as f:
                config = json.load(f)

            # Populate form fields
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

            # Load migration settings
            migration_enabled = config.get('migration_enabled', False)
            self.migration_enabled_checkbox.setChecked(migration_enabled)

            migration_commands = '\n'.join(config.get('migration_commands', []))
            self.migration_commands_input.setPlainText(migration_commands)

            run_commands = '\n'.join(config.get('run_commands', []))
            self.run_commands_input.setPlainText(run_commands)

            self.statusBar().showMessage(f"Configuration loaded from {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load configuration: {str(e)}")

    def _save_config(self):
        """Save current configuration to JSON file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Configuration", "deployment_config.json", "JSON files (*.json);;All files (*)"
        )

        if not file_path:
            return

        try:
            config = self._get_current_config()

            with open(file_path, 'w') as f:
                json.dump(config, f, indent=4)

            self.statusBar().showMessage(f"Configuration saved to {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save configuration: {str(e)}")

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

        return {
            'ec2_user': self.ec2_user_input.text(),
            'ec2_host': self.ec2_host_input.text(),
            'ec2_key_path': self.ec2_key_input.text(),
            'app_dir': self.app_dir_input.text(),
            'git_user': self.git_user_input.text(),
            'git_token': self.git_token_input.text(),
            'git_repo': self.git_repo_input.text(),
            'branch': self.branch_input.text(),
            'install_commands': install_commands,
            'migration_enabled': self.migration_enabled_checkbox.isChecked(),
            'migration_commands': migration_commands,
            'run_commands': run_commands
        }

    def _start_deployment(self):
        """Start the deployment process"""
        # Validate configuration
        config = self._get_current_config()

        required_fields = ['ec2_user', 'ec2_host', 'ec2_key_path', 'app_dir', 'git_repo', 'branch']
        missing_fields = [field for field in required_fields if not config.get(field)]

        if missing_fields:
            QMessageBox.warning(
                self, "Missing Configuration",
                f"Please fill in the following required fields: {', '.join(missing_fields)}"
            )
            return

        # Check migration commands if enabled
        if config.get('migration_enabled', False) and not config.get('migration_commands'):
            reply = QMessageBox.question(
                self, "Migration Commands",
                "Migration is enabled but no migration commands are specified. Continue anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return

        # Clear log and reset progress
        self.log_output.clear()
        self.progress_bar.setValue(0)

        # Start deployment worker
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
        # Auto-scroll to bottom
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


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)

    # Set application properties
    app.setApplicationName("Server Deployment Tool")
    app.setApplicationVersion("1.0")
    app.setOrganizationName("Deployment Tools")

    # Create and show main window
    window = DeploymentApp()
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
