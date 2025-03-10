#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo
echo "Welcome to the SSH Profile Manager (sshp) installation script!"
echo

check_go() {
  echo -e "${BLUE}Checking if Go is installed...${NC}"
  if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed. Please install Go or higher.${NC}"
    echo "You can download Go from https://golang.org/dl/"
    exit 1
  fi
}

check_dependencies() {
  echo -e "${BLUE}Checking for sshpass and expect...${NC}"

  SSHPASS_INSTALLED=false
  EXPECT_INSTALLED=false

  if command -v sshpass &> /dev/null; then
    echo -e "${GREEN}sshpass is installed.${NC}"
    SSHPASS_INSTALLED=true
  else
    echo -e "${YELLOW}sshpass is not installed. Password authentication will be manual or use expect.${NC}"
  fi

  if command -v expect &> /dev/null; then
    echo -e "${GREEN}expect is installed.${NC}"
    EXPECT_INSTALLED=true
  else
    echo -e "${YELLOW}expect is not installed. Password authentication will use sshpass or be manual.${NC}"
  fi

  if [ "$SSHPASS_INSTALLED" = false ] && [ "$EXPECT_INSTALLED" = false ]; then
    echo
    echo -e "${YELLOW}Note: Neither sshpass nor expect are installed.${NC}"
    echo "For automatic password authentication, install one of these tools:"
    echo
    OS=$(uname -s)
    if [ "$OS" = "Linux" ]; then
      echo "  For Debian/Ubuntu: sudo apt-get install sshpass"
      echo "  For Fedora: sudo dnf install sshpass"
      echo "  For CentOS/RHEL: sudo yum install sshpass"
    elif [ "$OS" = "Darwin" ]; then
      echo "  For macOS: brew install hudochenkov/sshpass/sshpass"
      echo "    or: brew install expect"
    fi
    echo
  fi
}

install_with_go_install() {
  echo -e "${BLUE}Installing sshp using go install...${NC}"

  MODULE_PATH="github.com/Salvadego/SshP/cmd/sshp"

  echo -e "${BLUE}Installing ...${NC}"

  GOPATH=$(go env GOPATH)
  if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    echo -e "${YELLOW}Note: $GOPATH/bin is not in your PATH.${NC}"
    echo "You may want to add it to your shell profile:"
    echo "  echo 'export PATH=\"\$PATH:$GOPATH/bin\"' >> ~/.bashrc"
    echo "  source ~/.bashrc"
  fi

  MODULE_SPEC="$MODULE_PATH@latest"
  go install "$MODULE_SPEC" || {
    echo -e "${RED}Error: Installation failed.${NC}"
    exit 1
  }

  echo -e "${GREEN}Installation successful!${NC}"

  if command -v sshp &> /dev/null; then
    echo -e "${GREEN}sshp is now available in your PATH.${NC}"
  else
    echo -e "${YELLOW}Note: sshp is installed but may not be in your PATH.${NC}"
    echo "The binary should be located at $GOPATH/bin/sshp"
    echo "Make sure $GOPATH/bin is in your PATH to use sshp from anywhere."
  fi
}

post_install_message() {
  echo
  echo -e "${GREEN}SSH Profile Manager (sshp) has been successfully installed!${NC}"
  echo
  echo "To get started, try the following commands:"
  echo
  echo "  Create completion for your shell:"
  echo "    source <(sshp completion bash)"
  echo "    # You may want to add it to your bashrc"
  echo
  echo "  Add a profile:"
  echo "    sshp add myserver --host example.com --user myusername"
  echo
  echo "  Connect to a server:"
  echo "    sshp connect myserver"
  echo
  echo "  List available profiles:"
  echo "    sshp list"
  echo
  echo "  For more help:"
  echo "    sshp --help"
  echo
  echo -e "${BLUE}Thank you for installing SSH Profile Manager!${NC}"
}

main() {
  check_go
  check_dependencies

  echo -e "${BLUE}Installation methods:${NC}"
  echo "1. Use go install (recommended)"
  echo "2. Exit"
  read -p "Select option (1/2): " OPTION

  case $OPTION in
    1)
      install_with_go_install
      post_install_message
      ;;
    2)
      echo -e "${BLUE}Installation cancelled.${NC}"
      exit 0
      ;;
    *)
      echo -e "${RED}Invalid option. Please select 1, 2, or 3.${NC}"
      exit 1
      ;;
  esac
}

main
