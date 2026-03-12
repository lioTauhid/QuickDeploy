from typing import Dict

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QTextEdit, QPushButton,
    QFileDialog, QMessageBox, QProgressBar, QGroupBox,
    QScrollArea, QSplitter, QCheckBox, QTabWidget, QInputDialog, QComboBox
)

from core.config_manager import ConfigManager
from core.ssh_manager import SSHConnectionManager
from ui.file_browser_tab import FileBrowserTab
from ui.terminal_tab import TerminalTab
from worker.deployment_worker import DeploymentWorker


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
