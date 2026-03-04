# QuickDeploy Setup Guide

This guide provides step-by-step instructions for setting up QuickDeploy on Windows, macOS, and Linux.

## Prerequisites

Before you begin, ensure you have:
- Python 3.7 or later installed
- SSH access to your remote server
- SSH private key file (`.pem` or similar)
- GitHub personal access token (if using GitHub)

## Windows Setup

### Step 1: Install Python

1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run the installer
3. **Important**: Check "Add Python to PATH" during installation
4. Verify installation by opening Command Prompt and typing:
   ```cmd
   python --version
   ```

### Step 2: Extract QuickDeploy

1. Extract the `app_updated.zip` file to a folder (e.g., `C:\QuickDeploy`)
2. Open Command Prompt and navigate to the folder:
   ```cmd
   cd C:\QuickDeploy
   ```

### Step 3: Run the Application

Double-click `install+run.bat` or run from Command Prompt:
```cmd
install+run.bat
```

The script will:
- Create a Python virtual environment
- Install required dependencies
- Launch the application

### Troubleshooting (Windows)

**"Python is not recognized"**:
- Reinstall Python and ensure "Add Python to PATH" is checked
- Or use the full path: `C:\Python311\python.exe app.py`

**"Permission denied" when running .bat file**:
- Right-click the .bat file and select "Run as administrator"

**PyQt6 installation fails**:
- Update pip: `python -m pip install --upgrade pip`
- Try: `pip install PyQt6==6.9.0`

## macOS Setup

### Step 1: Install Python

Using Homebrew (recommended):
```bash
brew install python3
```

Or download from [python.org](https://www.python.org/downloads/)

Verify installation:
```bash
python3 --version
```

### Step 2: Extract QuickDeploy

1. Extract the `app_updated.zip` file
2. Open Terminal and navigate to the folder:
   ```bash
   cd /path/to/QuickDeploy
   ```

### Step 3: Make Script Executable

```bash
chmod +x install+run.sh
```

### Step 4: Run the Application

```bash
./install+run.sh
```

Or directly:
```bash
python3 app.py
```

### Troubleshooting (macOS)

**"Command not found: python3"**:
- Install Python via Homebrew: `brew install python3`
- Or download from python.org

**PyQt6 installation fails**:
- Update pip: `python3 -m pip install --upgrade pip`
- Install Xcode Command Line Tools: `xcode-select --install`

**Application window doesn't appear**:
- Ensure you're running in a graphical environment (not SSH session)
- Try: `python3 -m PyQt6.examples.widgets` to test PyQt6

## Linux Setup

### Step 1: Install Python and Dependencies

**Ubuntu/Debian**:
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv
sudo apt-get install qt6-qpa-plugins  # For GUI support
```

**CentOS/RHEL**:
```bash
sudo yum install python3 python3-pip
sudo yum install qt6-qpa-plugins
```

**Fedora**:
```bash
sudo dnf install python3 python3-pip
sudo dnf install qt6-qpa-plugins
```

### Step 2: Extract QuickDeploy

1. Extract the `app_updated.zip` file
2. Open Terminal and navigate to the folder:
   ```bash
   cd /path/to/QuickDeploy
   ```

### Step 3: Make Script Executable

```bash
chmod +x install+run.sh
```

### Step 4: Run the Application

```bash
./install+run.sh
```

Or directly:
```bash
python3 app.py
```

### Troubleshooting (Linux)

**"No module named 'PyQt6'"**:
- Install: `pip3 install PyQt6`
- Or: `sudo pip3 install PyQt6`

**"Could not connect to display"**:
- Ensure X11/Wayland is available
- Check: `echo $DISPLAY`
- If empty, you're in a headless environment

**Qt platform plugin not found**:
- Install: `sudo apt-get install qt6-qpa-plugins`
- Or: `sudo yum install qt6-qpa-plugins`

## Initial Configuration

### Step 1: Create SSH Key (if needed)

If you don't have an SSH key:

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/deployment-key
```

### Step 2: Add Public Key to Remote Server

```bash
ssh-copy-id -i ~/.ssh/deployment-key.pub username@remote-host
```

Or manually add the contents of `~/.ssh/deployment-key.pub` to `~/.ssh/authorized_keys` on the remote server.

### Step 3: Create Configuration File

1. Launch QuickDeploy
2. Fill in the EC2/Server Configuration section:
   - **EC2 User**: Username on remote server (e.g., `ubuntu`, `ec2-user`)
   - **EC2 Host**: IP address or domain name
   - **SSH Key Path**: Path to your private key (e.g., `~/.ssh/deployment-key`)

3. Fill in Git Configuration:
   - **Git User**: Your GitHub username
   - **Git Token**: Your GitHub personal access token
   - **Git Repository**: Repository URL (e.g., `github.com/username/repo.git`)
   - **Branch**: Branch to deploy (e.g., `main`)

4. Configure Commands:
   - **Install Commands**: Commands to install dependencies
   - **Run Commands**: Commands to start your application

5. Click "💾 Save Config" to save your configuration

## First Deployment

1. **Connect**: Click the "Connect" button to test SSH connection
2. **Verify**: Check that "● Connected" appears in green
3. **Deploy**: Click "🚀 Deploy" to start deployment
4. **Monitor**: Watch the log output for any errors
5. **Verify**: SSH into your server and verify the application is running

## Common Workflows

### Deploying an Update

1. Make changes to your code
2. Push to GitHub
3. In QuickDeploy, click "🚀 Deploy"
4. The application will pull the latest changes and restart

### Editing a Remote File

1. Click the "📁 File Browser" tab
2. Navigate to the file
3. Right-click and select "✏️ Edit"
4. Make changes and click "💾 Save"

### Running Terminal Commands

1. Click the "💻 Terminal" tab
2. Type your command and press Enter
3. Use Up/Down arrows to navigate command history

### Uploading Files

1. Click the "📁 File Browser" tab
2. Navigate to the desired directory
3. Click "⬆ Upload"
4. Select file(s) from your computer

## Security Best Practices

1. **SSH Keys**: Keep your private keys secure and never commit them to version control
2. **GitHub Token**: Use a personal access token with minimal required permissions
3. **Configuration Files**: Store configuration files securely and never share them
4. **SSH Key Permissions**: Ensure SSH key has correct permissions:
   ```bash
   chmod 600 ~/.ssh/your-key.pem
   ```
5. **Remote Server**: Regularly update your remote server and keep SSH configured securely

## Getting Help

If you encounter issues:

1. Check the Troubleshooting section above
2. Review the README.md for detailed documentation
3. Check application logs for error messages
4. Contact support: liotauhid@gmail.com

## Next Steps

After successful setup, explore these features:

- **Terminal**: Execute commands on your remote server
- **File Browser**: Manage remote files and directories
- **File Editor**: Edit configuration files on the server
- **Deployment**: Automate your application deployment

Happy deploying! 🚀
