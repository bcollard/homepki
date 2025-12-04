package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var workDir string

var rootCmd = &cobra.Command{
	Use:   "homepki",
	Short: "A simple PKI management tool",
	Long:  `A tool to generate root certificates, intermediate certificates, and leaf certificates for both client and server.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&workDir, "workdir", "", "Working directory (default is $HOMEPKI_WORKDIR or ~/.homepki)")
}

func getEffectiveWorkDir() (string, error) {
	if workDir != "" {
		return workDir, nil
	}

	if envDir := os.Getenv("HOMEPKI_WORKDIR"); envDir != "" {
		return envDir, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".homepki"), nil
}
