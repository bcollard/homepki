package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var workDir string
var versionString string

var rootCmd = &cobra.Command{
	Use:   "homepki",
	Short: "A simple PKI management tool",
	Long:  `A tool to generate root certificates, intermediate certificates, and leaf certificates for both client and server.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Flags have been parsed and validated by now, so any later error is a
		// runtime failure rather than a usage mistake — print it on its own
		// instead of burying it under the help text.
		cmd.SilenceUsage = true
	},
}

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Print version information",
	Aliases: []string{"v"},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("homepki " + versionString)
	},
}

func SetVersion(version, commit, date string) {
	versionString = version + " (" + commit + ", " + date + ")"
	rootCmd.Version = versionString
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&workDir, "workdir", "", "Working directory (default is $HOMEPKI_WORKDIR or ~/.homepki)")
	rootCmd.AddCommand(versionCmd)
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
