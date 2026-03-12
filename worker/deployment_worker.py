import os
from typing import Dict, List

from PyQt6.QtCore import QThread, pyqtSignal
from paramiko import SSHClient, AutoAddPolicy


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
