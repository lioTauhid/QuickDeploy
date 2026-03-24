import os
import sys

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication
from ui.deployment_app import DeploymentApp


def resource_path(relative_path: str) -> str:
    """Resolve asset path for dev and PyInstaller --onefile frozen env."""
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("QuickDeploy (Remote management, CI-CD)")
    app.setApplicationVersion("0.9")
    app.setOrganizationName("liotauhid@gmail.com")

    icon_path = resource_path("assets/logo.png")
    print(f"[DEBUG] Icon path: {icon_path}, Exists: {os.path.exists(icon_path)}")
    app.setWindowIcon(QIcon(icon_path))

    window = DeploymentApp()
    window.setWindowIcon(QIcon(icon_path))
    window.setWindowTitle("QuickDeploy (Remote management, CI-CD)")
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
