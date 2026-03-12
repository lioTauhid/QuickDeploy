import platform
import subprocess


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
