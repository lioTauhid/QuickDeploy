import sys

from PyQt6.QtWidgets import (
    QApplication
)

from ui.deployment_app import DeploymentApp


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
