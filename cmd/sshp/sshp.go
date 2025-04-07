package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"
)

type Profile struct {
	Host         string            `yaml:"host"`
	Port         int               `yaml:"port"`
	User         string            `yaml:"user"`
	IdentityFile string            `yaml:"identity_file,omitempty"`
	Password     string            `yaml:"password,omitempty"`
	Options      map[string]string `yaml:"options,omitempty"`
}

type Config struct {
	Profiles map[string]Profile `yaml:"profiles"`
}

var (
	cfgFile     string
	config      Config
	keyFile     string
	encryptKey  []byte
	initialized bool
)

func main() {
	Execute()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "sshp",
	Short: "SSH Profile Manager",
	Long: `SSH Profile Manager is a tool to manage and connect to different SSH servers
    using predefined profiles stored in a configuration file.`,
}

var connectCmd = &cobra.Command{
	Use:   "connect [profile-name]",
	Short: "Connect to a server using a profile",
	Long:  `Connect to an SSH server using a predefined profile from your configuration.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profileName := args[0]
		connectToProfile(profileName)
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available profiles",
	Long:  `Display a list of all available SSH profiles from your configuration.`,
	Run: func(cmd *cobra.Command, args []string) {
		listProfiles()
	},
}

var addCmd = &cobra.Command{
	Use:   "add [profile-name]",
	Short: "Add a new SSH profile",
	Long:  `Add a new SSH profile to your configuration file.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profileName := args[0]

		host, _ := cmd.Flags().GetString("host")
		port, _ := cmd.Flags().GetInt("port")
		user, _ := cmd.Flags().GetString("user")
		identityFile, _ := cmd.Flags().GetString("identity-file")
		password, _ := cmd.Flags().GetString("password")
		promptPassword, _ := cmd.Flags().GetBool("prompt-password")
		options, _ := cmd.Flags().GetStringArray("option")

		if promptPassword {
			fmt.Print("Enter SSH password: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				fmt.Println("Error reading password:", err)
				os.Exit(1)
			}
			password = string(passwordBytes)
		}

		addProfile(profileName, host, port, user, identityFile, password, options)
	},
}

var removeCmd = &cobra.Command{
	Use:   "remove [profile-name]",
	Short: "Remove an SSH profile",
	Long:  `Remove an SSH profile from your configuration file.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profileName := args[0]
		removeProfile(profileName)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sshp.yaml)")

	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(removeCmd)

	addCmd.Flags().String("host", "", "SSH server hostname or IP address")
	addCmd.Flags().Int("port", 22, "SSH server port")
	addCmd.Flags().String("user", "", "SSH username")
	addCmd.Flags().String("identity-file", "", "SSH identity file path")
	addCmd.Flags().String("password", "", "SSH password (optional, will be securely encrypted)")
	addCmd.Flags().Bool("prompt-password", false, "Prompt for password instead of providing in command line")
	addCmd.Flags().StringArray("option", []string{}, "Additional SSH options in key=value format")

	addCmd.MarkFlagRequired("host")
	addCmd.MarkFlagRequired("user")
}

func initConfig() {

	config = Config{
		Profiles: make(map[string]Profile),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	keyFile = filepath.Join(home, ".sshp.key")
	initEncryptionKey()

	if cfgFile != "" {

		viper.SetConfigFile(cfgFile)
	} else {

		viper.AddConfigPath(home)
		viper.SetConfigName(".sshp")
		viper.SetConfigType("yaml")
		cfgFile = filepath.Join(home, ".sshp.yaml")
	}

	if _, err := os.Stat(cfgFile); err == nil {

		data, err := os.ReadFile(cfgFile)
		if err != nil {
			fmt.Println("Error reading config file:", err)
			os.Exit(1)
		}

		err = yaml.Unmarshal(data, &config)
		if err != nil {
			fmt.Println("Error parsing config file:", err)
			os.Exit(1)
		}
	} else if os.IsNotExist(err) {

		saveConfig()
	} else {
		fmt.Println("Error checking config file:", err)
		os.Exit(1)
	}

	for name, profile := range config.Profiles {
		if profile.Options == nil {
			profile.Options = make(map[string]string)
			config.Profiles[name] = profile
		}
	}

	initialized = true
}

func initEncryptionKey() {

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {

		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fmt.Println("Error generating encryption key:", err)
			os.Exit(1)
		}

		err = os.WriteFile(keyFile, []byte(hex.EncodeToString(key)), 0600)
		if err != nil {
			fmt.Println("Error saving encryption key:", err)
			os.Exit(1)
		}

		encryptKey = key
	} else {

		data, err := os.ReadFile(keyFile)
		if err != nil {
			fmt.Println("Error reading encryption key:", err)
			os.Exit(1)
		}

		key, err := hex.DecodeString(string(data))
		if err != nil {
			fmt.Println("Error decoding encryption key:", err)
			os.Exit(1)
		}

		encryptKey = key
	}
}

func encryptPassword(password string) string {
	if password == "" {
		return ""
	}

	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		fmt.Println("Error creating cipher:", err)
		os.Exit(1)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error creating GCM:", err)
		os.Exit(1)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println("Error creating nonce:", err)
		os.Exit(1)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(password), nil)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func decryptPassword(encryptedPassword string) string {
	if encryptedPassword == "" {
		return ""
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {

		return encryptedPassword
	}

	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		fmt.Println("Error creating cipher:", err)
		return ""
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error creating GCM:", err)
		return ""
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {

		return encryptedPassword
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {

		return encryptedPassword
	}

	return string(plaintext)
}

func saveConfig() {
	data, err := yaml.Marshal(config)
	if err != nil {
		fmt.Println("Error marshaling config:", err)
		os.Exit(1)
	}

	err = os.WriteFile(cfgFile, data, 0644)
	if err != nil {
		fmt.Println("Error writing config file:", err)
		os.Exit(1)
	}
}

func connectToProfile(profileName string) {
	profile, ok := config.Profiles[profileName]
	if !ok {
		fmt.Printf("Profile '%s' not found. Available profiles: %v\n", profileName, getProfileNames())
		os.Exit(1)
	}

	args := []string{}

	args = append(args, fmt.Sprintf("%s@%s", profile.User, profile.Host))

	if profile.Port != 22 {
		args = append(args, "-p", fmt.Sprintf("%d", profile.Port))
	}

	if profile.IdentityFile != "" {
		args = append(args, "-i", profile.IdentityFile)
	}

	password := decryptPassword(profile.Password)

	for key, value := range profile.Options {
		if value == "" {
			args = append(args, "-o", key)
		} else {
			args = append(args, "-o", fmt.Sprintf("%s=%s", key, value))
		}
	}

	var err error
	regularSSHAttempted := false

	tryRegularSSH := func() error {
		regularSSHAttempted = true
		fmt.Printf("Connecting to profile: %s (%s@%s:%d)...\n", profileName, profile.User, profile.Host, profile.Port)
		cmd := exec.Command("ssh", args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	if password != "" {
		sshpassPath, err := exec.LookPath("sshpass")
		if err == nil {

			sshpassArgs := []string{"-p", password, "ssh"}
			sshpassArgs = append(sshpassArgs, args...)

			cmd := exec.Command(sshpassPath, sshpassArgs...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			fmt.Printf("Connecting to profile: %s (%s@%s:%d) with password authentication...\n",
				profileName, profile.User, profile.Host, profile.Port)

			err = cmd.Run()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 6 {
					fmt.Println("Initial connection failed with exit status 6. Trying direct SSH login...")
					err = tryRegularSSH()
				} else {
					fmt.Println("Error connecting to SSH server:", err)
					os.Exit(1)
				}
			}

			return
		} else {

			expectPath, err := exec.LookPath("expect")
			if err == nil {

				expectScript := fmt.Sprintf(`
                    spawn ssh %s
                    expect "password:"
                    send "%s\r"
                    interact
                    `, strings.Join(args, " "), password)

				tmpfile, err := os.CreateTemp("", "sshp-*.exp")
				if err != nil {
					fmt.Println("Error creating temporary file:", err)
				} else {
					defer os.Remove(tmpfile.Name())

					if _, err := tmpfile.Write([]byte(expectScript)); err != nil {
						fmt.Println("Error writing expect script:", err)
					}

					if err := tmpfile.Close(); err != nil {
						fmt.Println("Error closing temporary file:", err)
					}

					os.Chmod(tmpfile.Name(), 0700)

					cmd := exec.Command(expectPath, tmpfile.Name())
					cmd.Stdin = os.Stdin
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr

					fmt.Printf("Connecting to profile: %s (%s@%s:%d) with expect script...\n",
						profileName, profile.User, profile.Host, profile.Port)

					err = cmd.Run()
					if err != nil {
						if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 6 {
							fmt.Println("Initial connection failed with exit status 6. Trying direct SSH login...")
							err = tryRegularSSH()
						} else {
							fmt.Println("Error running expect script:", err)
							os.Exit(1)
						}
					}

					return
				}
			} else {
				fmt.Println("Note: Neither 'sshpass' nor 'expect' found. Trying direct SSH connection...")
			}
		}
	}

	if !regularSSHAttempted {
		err = tryRegularSSH()
		if err != nil {
			fmt.Println("Error connecting to SSH server:", err)
			os.Exit(1)
		}
	}
}

func getProfileNames() []string {
	names := make([]string, 0, len(config.Profiles))
	for name := range config.Profiles {
		names = append(names, name)
	}
	return names
}

func listProfiles() {
	if len(config.Profiles) == 0 {
		fmt.Println("No profiles configured. Use 'add' command to create a profile.")
		return
	}

	fmt.Println("Available profiles:")
	fmt.Println("------------------")

	for name, profile := range config.Profiles {
		fmt.Printf("- %s: %s@%s:%d", name, profile.User, profile.Host, profile.Port)
		if profile.IdentityFile != "" {
			fmt.Printf(" (using key: %s)", profile.IdentityFile)
		}
		if profile.Password != "" {
			fmt.Printf(" (using password auth)")
		}
		fmt.Println()
	}
}

func addProfile(name, host string, port int, user, identityFile string, password string, options []string) {

	profile := Profile{
		Host:         host,
		Port:         port,
		User:         user,
		IdentityFile: identityFile,
		Options:      make(map[string]string),
	}

	if password != "" {
		profile.Password = encryptPassword(password)
	}

	if profile.Options == nil {
		profile.Options = make(map[string]string)
	}

	for _, opt := range options {
		parts := strings.SplitN(opt, "=", 2)
		if len(parts) == 1 {
			profile.Options[parts[0]] = ""
		} else {
			profile.Options[parts[0]] = parts[1]
		}
	}

	if _, exists := config.Profiles[name]; exists {
		fmt.Printf("Profile '%s' already exists. Do you want to overwrite it? (y/N): ", name)
		var response string
		fmt.Scanln(&response)

		if strings.ToLower(response) != "y" {
			fmt.Println("Operation cancelled.")
			return
		}
	}

	config.Profiles[name] = profile

	saveConfig()

	fmt.Printf("Profile '%s' added successfully.\n", name)
}

func removeProfile(name string) {
	if _, exists := config.Profiles[name]; !exists {
		fmt.Printf("Profile '%s' does not exist.\n", name)
		return
	}

	fmt.Printf("Are you sure you want to remove profile '%s'? (y/N): ", name)
	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) != "y" {
		fmt.Println("Operation cancelled.")
		return
	}

	delete(config.Profiles, name)
	saveConfig()

	fmt.Printf("Profile '%s' removed successfully.\n", name)
}
