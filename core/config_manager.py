import json
import os
import sys
from pathlib import Path
from typing import Dict, List


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
