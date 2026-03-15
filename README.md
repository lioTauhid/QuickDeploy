<h1 align="center">
  <a><img src="https://github.com/lioTauhid/QuickDeploy/blob/main/assets/faeture-graphics.png?raw=true" alt="Logo" width="400"></a>
</h1>

# QuickDeploy - Remote Management & CI-CD Tool

A PyQt6 desktop GUI application for automating web app deployment to remote servers (EC2, VPS, etc.). This tool allows
you to deploy multiple web applications, manage remote files, and access an interactive terminal—all from a single
interface.

## Features

- **GUI Interface**: User-friendly PyQt6 interface for easy configuration
- **JSON Configuration**: Store deployment settings in JSON files for reusability
- **SSH Deployment**: Secure SSH connection to remote instances using key-based authentication
- **Real-time Logging**: View deployment progress and logs in real-time
- **Multi-app Support**: Deploy different web apps by switching configuration files
- **Git Integration**: Automatic git clone/pull operations
- **Custom Commands**: Configure install, migration, and run commands per application
- **Migration Control**: Enable/disable migration commands with checkbox
- **Interactive Terminal**: Full SSH terminal access with command history
- **File Browser**: Browse, upload, download, and manage remote files
- **File Editor**: Edit remote files directly with a built-in text editor
- **File Rename**: Rename files and directories on the remote server
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Requirements

- Python 3.7+
- PyQt6
- paramiko
- SSH access to remote instance
- Git repository with your web application

## Installation

### Prerequisites

Ensure you have Python 3.7 or later installed on your system.

### Step 1: How To Use

To clone and run this application, you'll need [Git](https://git-scm.com) installed on your computer. \
From your command line:

```bash
# Clone this repository
git clone https://github.com/lioTauhid/QuickDeploy
```

### Step 2: Install Required Python Packages

```bash
pip3 install -r requirements.txt
```

## Usage

### Running the Application

#### On Linux/macOS:

```bash
chmod +x install+run.sh
./install+run.sh
```

Or directly:

```bash
python3 app.py
```

#### On Windows:

Double-click `install+run.bat` or run:

```cmd
python app.py
```

**Note**: This application requires a desktop environment with GUI support (X11/Wayland on Linux, native on
macOS/Windows).

### Configuration

A sample JSON configuration file with your deployment settings:

```json
{
  "ec2_user": "ubuntu",
  "ec2_host": "your-ec2-ip-or-domain",
  "ec2_key_path": "~/path/to/your/key.pem",
  "app_dir": "/home/ubuntu/your-app-directory",
  "git_user": "your-github-username",
  "git_token": "your-github-personal-access-token",
  "git_repo": "github.com/your-username/your-repo.git",
  "branch": "main",
  "install_commands": [
    "pip3 install -r requirements.txt",
    "npm install"
  ],
  "migration_enabled": true,
  "migration_commands": [
    "python3 manage.py migrate",
    "python3 manage.py collectstatic --noinput"
  ],
  "run_commands": [
    "pkill -f 'your-app-process' || true",
    "nohup python3 app.py &"
  ]
}
```

### Deployment Process

1. **Load Configuration**: Click "Load Config" and select your JSON file
2. **Review Settings**: Verify all fields are correctly populated
3. **Connect to Server**: Click "Connect" to establish SSH connection
4. **Enable/Disable Migrations**: Check or uncheck the "Enable Migration Commands" checkbox
5. **Deploy**: Click the "🚀 Deploy" button to start deployment
6. **Monitor Progress**: Watch the real-time log output and progress bar
7. **Save Configuration**: Save current settings for future use

### Terminal Usage

1. **Connect to Server**: First, establish an SSH connection using the "Connect" button
2. **Execute Commands**: Type commands in the terminal and press Enter
3. **Command History**: Use Up/Down arrow keys to navigate command history
4. **Clear Terminal**: Click the "Clear" button to clear terminal output

**Supported Commands**: All standard shell commands including:

- `ls`, `ll`, `cd`, `pwd`, `mkdir`, `rm`, `cp`, `mv`
- `git`, `npm`, `pip`, `python`, etc.

### File Browser Usage

1. **Connect to Server**: First, establish an SSH connection
2. **Navigate**: Click on folders to navigate, use "Back" button to go up
3. **Upload Files**: Click "⬆ Upload" to upload files from your computer
4. **Download Files**: Right-click on a file and select "📥 Download"
5. **Edit Files**: Right-click on a file and select "✏️ Edit" to open the file editor
6. **Rename Files**: Right-click on a file/folder and select "✏️ Rename"
7. **Delete Files**: Right-click on a file/folder and select "🗑️ Delete"
8. **Create Folders**: Click "📁 New Folder" to create a new directory

## Configuration Fields

| Field                | Description                                           | Required |
|----------------------|-------------------------------------------------------|----------|
| `ec2_user`           | Remote instance username (ubuntu/ec2-user/root)       | Yes      |
| `ec2_host`           | Remote instance public IP or domain name              | Yes      |
| `ec2_key_path`       | Path to SSH private key file                          | Yes      |
| `app_dir`            | Directory path on remote instance for the application | Yes      |
| `git_user`           | GitHub username                                       | Yes      |
| `git_token`          | GitHub Personal Access Token                          | Yes      |
| `git_repo`           | Git repository URL                                    | Yes      |
| `branch`             | Git branch to deploy                                  | Yes      |
| `install_commands`   | List of commands to install dependencies              | No       |
| `migration_enabled`  | Enable/disable migration commands                     | No       |
| `migration_commands` | List of migration commands to run                     | No       |
| `run_commands`       | List of commands to start/restart the app             | No       |

## Deployment Steps

The application performs the following steps automatically:

1. **SSH Connection**: Connects to remote instance using provided credentials
2. **Git Operations**:
    - If app directory exists: `git pull` latest changes
    - If not: `git clone` the repository
3. **Dependencies**: Runs install commands (e.g., pip install, npm install)
4. **Migrations** (if enabled): Runs migration commands (e.g., database migrations, static file collection)
5. **Application Start**: Executes run commands to start/restart the application

## File Editor Features

The built-in file editor allows you to:

- View file contents
- Edit remote files directly
- Save changes back to the server
- Support for text files (code, config, logs, etc.)

**Supported File Types**: Any text-based file (.py, .js, .json, .yaml, .conf, .log, etc.)

## Cross-Platform Compatibility

This application has been tested and is compatible with:

- **Windows 10/11**: Use `install+run.bat` or run directly with `python app.py`
- **macOS**: Use `install+run.sh` or run directly with `python3 app.py`
- **Linux** (Ubuntu, Debian, CentOS, etc.): Use `install+run.sh` or run directly with `python3 app.py`

### Platform-Specific Notes

**Windows**:

- Ensure Python is added to PATH
- Use forward slashes (/) in SSH key paths or use raw strings
- Git Bash or WSL recommended for better compatibility

**macOS**:

- May require XQuartz for X11 support (usually not needed)
- Use `python3` command instead of `python`

**Linux**:

- Ensure X11 or Wayland is available for GUI
- May need to install Qt platform plugins: `sudo apt-get install qt6-qpa-plugins`

## Security Notes

- Store SSH private keys securely and never commit them to version control
- Use GitHub Personal Access Tokens instead of passwords
- Keep configuration files secure (they contain sensitive credentials)
- Consider using environment variables for sensitive data in production
- Restrict SSH key file permissions: `chmod 600 ~/.ssh/your-key.pem`

## Troubleshooting

### Common Issues

1. **SSH Connection Failed**
    - Verify remote instance is running and accessible
    - Check SSH key path and permissions
    - Ensure security groups allow SSH access (port 22)
    - Verify username matches the instance OS (ubuntu, ec2-user, etc.)

2. **Git Authentication Failed**
    - Verify GitHub username and token
    - Ensure token has repository access permissions
    - Check if token has expired

3. **Terminal Commands Not Working**
    - Ensure shell is properly initialized
    - Try using full command paths (e.g., `/usr/bin/python3`)
    - Check if command requires interactive input

4. **File Editor Not Opening**
    - Ensure file is readable on remote server
    - Check file permissions
    - Try with a smaller file first

5. **Application Won't Start (GUI)**
    - Requires desktop environment with X11/Wayland (Linux)
    - Install required Qt platform plugins
    - Check if DISPLAY variable is set (Linux)
    - For headless servers, use the core logic programmatically

6. **Permission Denied Errors**
    - Check SSH key permissions: `chmod 600 ~/.ssh/your-key.pem`
    - Verify user has permissions for the app directory
    - Use `sudo` in commands if necessary (with caution)

## File Structure

```
├── app.py
├── archive
│   └── app-old.py
├── assets
│   ├── faeture-graphics.png
│   └── logo.png
├── core
│   ├── config_manager.py
│   ├── __init__.py
│   └── ssh_manager.py
├── install+run.bat
├── install+run.sh
├── LICENSE
├── README.md
├── requirements.txt
├── SETUP_GUIDE.md
├── ui
│   ├── deployment_app.py
│   ├── file_browser_tab.py
│   ├── file_edit_dialog.py
│   ├── __init__.py
│   └── terminal_tab.py
└── worker
    ├── deployment_worker.py
    ├── file_operation_worker.py
    ├── __init__.py
    └── native_terminal_launcher.py
```

## Configuration Storage

Configurations are stored in OS-specific directories:

- **Windows**: `C:\Users\<Username>\AppData\Local\DeploymentTool\`
- **macOS**: `~/Library/Application Support/DeploymentTool/`
- **Linux**: `~/.config/deployment-tool/`

## Version History

### Version 0.9 (Latest)

- ✅ Added file editor with popup window
- ✅ Added rename button to file browser
- ✅ Fixed terminal bugs (improved shell initialization)
- ✅ Enhanced cross-platform compatibility
- ✅ Improved terminal command handling
- ✅ Added file read/write operations via SFTP

### Version 0.8

- Initial release with deployment, terminal, and file browser

## Support

For issues, questions, or feature requests, please contact: liotauhid@gmail.com

## Contributing

Contributions are welcome! Feel free to modify, and submit pull requests.

## License

This project is licensed under the GPL
License - [GPL](https://raw.githubusercontent.com/lioTauhid/QuickDeploy/refs/heads/main/LICENSE)

---

> GitHub [@lioTauhid](https://github.com/lioTauhid) &nbsp;&middot;&nbsp;
> LinkedIn [@Md Tauhid](https://www.linkedin.com/in/md-tauhid-5861b8140/)

**Made with ❤️ for developers and DevOps engineers**
