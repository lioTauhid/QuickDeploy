# Changelog

All notable changes to this project will be documented in this file.

## [1.0] - 2026-03-04

### Added
- **File Editor Feature**: New popup window for editing remote files directly
  - View file contents from remote server
  - Edit and save changes back to server
  - Support for all text-based files
  - Integrated with file browser (right-click menu and double-click)

- **File Rename Feature**: Ability to rename files and directories
  - Right-click context menu option
  - Integrated into file browser workflow
  - Works for both files and directories

- **Terminal Bug Fixes**:
  - Fixed issue with commands like "ll" not working at the beginning
  - Improved shell initialization with proper environment variables
  - Added support for shell aliases and bash profile sourcing
  - Enhanced command timeout handling
  - Better handling of shell channel creation

- **Cross-Platform Support**:
  - Windows batch script (`install+run.bat`)
  - Linux/macOS shell script (`install+run.sh`)
  - OS-specific configuration directory handling
  - Proper path handling using `pathlib.Path`
  - Platform-specific documentation

- **SFTP File Operations**:
  - Direct file read/write via SFTP
  - Better performance for file operations
  - Proper encoding handling for text files

### Changed
- Updated application version to 1.0
- Enhanced shell channel initialization
  - Changed terminal type from 'dumb' to 'xterm-256color'
  - Added proper PS1 prompt setting
  - Added shell alias expansion support
  - Added initialization delay for shell readiness

- Improved file browser UI
  - Better error handling and user feedback
  - Enhanced status messages

- Updated documentation
  - Comprehensive README with all new features
  - Cross-platform setup instructions
  - Troubleshooting guide
  - Security notes

### Fixed
- Terminal command execution issues with short commands (e.g., "ll")
- Shell initialization problems on different systems
- File path handling across Windows, macOS, and Linux
- Configuration directory creation on all platforms

### Improved
- Error messages and user feedback
- Cross-platform compatibility testing
- Code organization and comments
- Documentation completeness

## [0.8] - Previous Release

### Features
- SSH deployment to remote servers
- Interactive terminal access
- File browser with upload/download
- Configuration management
- Real-time deployment logging
- Git integration
- Custom command execution
- Migration command support

---

## Migration Guide from 0.8 to 1.0

No breaking changes. Simply replace the old `app.py` with the new version. Existing configurations will continue to work.

### New Features to Try:
1. **Edit Files**: Right-click on any file in the file browser and select "✏️ Edit"
2. **Rename Files**: Right-click on files/folders and select "✏️ Rename"
3. **Terminal**: Try commands like "ll" - they should now work properly

### Configuration Files:
- Old configurations in `~/.config/deployment-tool/` (Linux) will be automatically found
- Configurations are automatically migrated to the new version
