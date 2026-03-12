import os
from typing import Optional

from paramiko import SSHClient, AutoAddPolicy, SFTPClient


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
