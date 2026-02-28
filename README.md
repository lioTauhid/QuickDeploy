# Web App Deployment Tool

A PyQt6 desktop GUI application for automating web app deployment to EC2 servers. This tool allows you to deploy multiple web applications by simply updating JSON configuration files.

## Features

- **GUI Interface**: User-friendly PyQt6 interface for easy configuration
- **JSON Configuration**: Store deployment settings in JSON files for reusability
- **SSH Deployment**: Secure SSH connection to EC2 instances using key-based authentication
- **Real-time Logging**: View deployment progress and logs in real-time
- **Multi-app Support**: Deploy different web apps by switching configuration files
- **Git Integration**: Automatic git clone/pull operations
- **Custom Commands**: Configure install, migration, and run commands per application
- **Migration Control**: Enable/disable migration commands with checkbox

## Requirements

- Python 3.7+
- PyQt6
- paramiko
- SSH access to EC2 instance
- Git repository with your web application

## Installation

1. Install required Python packages:
```bash
pip3 install PyQt6 paramiko
```

2. Download the application files:
- `deployment_app.py` - Main application
- `deployment_config.json` - Example configuration
- `example_config.json` - Template for new configurations

## Usage

### 1. Running the Application

```bash
python3 app.py
```

**Note**: This application requires a desktop environment with GUI support. If you're running on a server without GUI, you can still use the core deployment logic by importing the `DeploymentWorker` class.

### 2. Configuration

Create or modify a JSON configuration file with your deployment settings:

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

### 3. Deployment Process

1. **Load Configuration**: Click "Load Config" and select your JSON file
2. **Review Settings**: Verify all fields are correctly populated
3. **Enable/Disable Migrations**: Check or uncheck the "Enable Migration Commands" checkbox
4. **Deploy**: Click the "Deploy" button to start deployment
5. **Monitor Progress**: Watch the real-time log output and progress bar
6. **Save Configuration**: Save current settings for future use

## Configuration Fields

| Field | Description | Required |
|-------|-------------|----------|
| `ec2_user` | EC2 instance username (ubuntu/ec2-user) | Yes |
| `ec2_host` | EC2 public IP or domain name | Yes |
| `ec2_key_path` | Path to SSH private key file | Yes |
| `app_dir` | Directory path on EC2 for the application | Yes |
| `git_user` | GitHub username | Yes |
| `git_token` | GitHub Personal Access Token | Yes |
| `git_repo` | Git repository URL | Yes |
| `branch` | Git branch to deploy | Yes |
| `install_commands` | List of commands to install dependencies | No |
| `migration_enabled` | Enable/disable migration commands | No |
| `migration_commands` | List of migration commands to run | No |
| `run_commands` | List of commands to start/restart the app | No |

## Deployment Steps

The application performs the following steps automatically:

1. **SSH Connection**: Connects to EC2 instance using provided credentials
2. **Git Operations**: 
   - If app directory exists: `git pull` latest changes
   - If not: `git clone` the repository
3. **Dependencies**: Runs install commands (e.g., pip install, npm install)
4. **Migrations** (if enabled): Runs migration commands (e.g., database migrations, static file collection)
5. **Application Start**: Executes run commands to start/restart the application

## Migration Commands

Migration commands are executed after installation but before starting the application. Common use cases include:

- Database migrations: `python3 manage.py migrate`

To use migration commands:
1. Check the "Enable Migration Commands" checkbox
2. Enter your migration commands (one per line)
3. Save the configuration for future use

## Security Notes

- Store SSH private keys securely
- Use GitHub Personal Access Tokens instead of passwords
- Keep configuration files secure (they contain sensitive credentials)
- Consider using environment variables for sensitive data in production

## Troubleshooting

### Common Issues

1. **SSH Connection Failed**
   - Verify EC2 instance is running and accessible
   - Check SSH key path and permissions
   - Ensure security groups allow SSH access

2. **Git Authentication Failed**
   - Verify GitHub username and token
   - Ensure token has repository access permissions

3. **Migration Commands Failed**
   - Check migration commands syntax
   - Verify database connectivity
   - Ensure proper permissions for migration operations

4. **Application Won't Start (GUI)**
   - Requires desktop environment with X11/Wayland
   - Install required Qt platform plugins
   - For headless servers, use the core logic programmatically

## File Structure

```
deployment-tool/
├── deployment_app.py              # Main PyQt6 application
├── example_config.json            # Example Configuration template
├── requirements.txt               # Python dependencies
├── install+run.sh                 # Installation script and run
└── README.md                      # This documentation
```