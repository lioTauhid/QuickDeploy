import os

from PyQt6.QtCore import QThread, pyqtSignal

from core.ssh_manager import SSHConnectionManager


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
