# SSH Profile Manager (sshp)

A command-line tool to manage and easily connect to multiple SSH servers using predefined profiles.

## Features

- Store and manage multiple SSH connection profiles
- Connect to servers with a single command
- Support for key-based and password authentication
- Securely encrypt stored passwords
- Add custom SSH options for each profile
- Simple command-line interface

## Installation

### Prerequisites

- Go
- For password authentication:
  - `sshpass` or `expect` (optional, but recommended for password-based logins)

### Quick Installation

You can install SSH Profile Manager with a single command:

```bash
curl -sSL https://raw.githubusercontent.com/Salvadego/SshP/main/install.sh | bash
```

This script will:
1. Check for Go and optional dependencies
2. Install the tool using `go install`
3. Verify that the installation was successful

### Manual Installation

#### Option 1: Using Go Install (Recommended)

```bash
go install github.com/Salvadego/SshP@latest
```

#### Option 2: Building from source

```bash
git clone https://github.com/Salvadego/SshP.git
cd sshp
go build -o sshp .

# Move the binary to a location in your PATH
sudo mv sshp /usr/local/bin/
```

## Configuration

SSH Profile Manager stores configurations in `~/.sshp.yaml` and encryption keys in `~/.sshp.key`.
These files will be automatically created on first run.

## Usage

### Adding a profile

```bash
# Basic usage
sshp add myserver --host example.com --user myusername

# With key authentication
sshp add myserver --host example.com --user myusername --identity-file ~/.ssh/id_rsa

# With password authentication (securely prompted)
sshp add myserver --host example.com --user myusername --prompt-password

# With custom port
sshp add myserver --host example.com --user myusername --port 2222

# With additional SSH options
sshp add myserver --host example.com --user myusername --option "StrictHostKeyChecking=no" --option "ForwardAgent=yes"
```

### Connecting to a server

```bash
sshp connect myserver
```

### Listing available profiles

```bash
sshp list
```

### Removing a profile

```bash
sshp remove myserver
```

## Security Notes

- Passwords are encrypted using AES-GCM with a randomly generated 32-byte key
- The encryption key is stored in `~/.sshp.key` with 0600 permissions
- Consider using SSH keys instead of passwords when possible

## Advanced Usage

### Using a custom configuration file

```bash
sshp --config /path/to/config.yaml list
```

## Troubleshooting

### Password Authentication

For password authentication to work automatically:

1. Install `sshpass`: 
   - Debian/Ubuntu: `sudo apt-get install sshpass`
   - macOS: `brew install hudochenkov/sshpass/sshpass`

2. If `sshpass` is not available, the tool will try to use `expect`:
   - Debian/Ubuntu: `sudo apt-get install expect`
   - macOS: `brew install expect`

3. If neither is available, you'll be prompted to enter the password manually.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
