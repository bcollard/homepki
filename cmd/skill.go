package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// skillMD holds the embedded SKILL.md, injected from main via SetSkill.
var skillMD string

// SetSkill provides the Agent Skill definition embedded in the binary.
func SetSkill(md string) {
	skillMD = md
}

// claudeSkillDir returns Claude Code's user skills directory for homepki.
func claudeSkillDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "skills", "homepki")
}

var skillCmd = &cobra.Command{
	Use:   "skill",
	Short: "Install the homepki Agent Skill for AI coding tools",
	Long: `Manage the homepki Agent Skill — a portable capability description that
teaches AI coding tools (e.g. Claude Code) how to use homepki to issue local
development TLS certificates from a three-tier PKI.`,
}

var skillInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the homepki Agent Skill into an AI coding tool",
	Long: `Install the homepki Agent Skill (SKILL.md) into your AI coding tool's
skills directory, so agents know how to drive homepki without you explaining it
each session.

By default it installs into Claude Code's user skills directory:

  ~/.claude/skills/homepki/SKILL.md

Use --print to emit the skill to stdout instead (pipe it anywhere).`,
	Example: `  # Install for Claude Code
  homepki skill install

  # Overwrite an already-installed skill
  homepki skill install --force

  # Write it somewhere else
  homepki skill install --print > ./SKILL.md`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if skillPrint {
			fmt.Fprint(os.Stdout, skillMD)
			return nil
		}
		if !skillClaude {
			return fmt.Errorf("no install target selected (pass --claude, or --print)")
		}
		return installClaudeSkill(skillForce)
	},
}

var skillPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print where the homepki Agent Skill is installed for Claude Code",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(filepath.Join(claudeSkillDir(), "SKILL.md"))
		return nil
	},
}

var (
	skillClaude bool
	skillPrint  bool
	skillForce  bool
)

func installClaudeSkill(force bool) error {
	dir := claudeSkillDir()
	dest := filepath.Join(dir, "SKILL.md")

	if _, err := os.Stat(dest); err == nil && !force {
		fmt.Printf("Skill already installed at %s (use --force to overwrite)\n", dest)
		return nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating skill dir: %w", err)
	}
	if err := os.WriteFile(dest, []byte(skillMD), 0o644); err != nil {
		return fmt.Errorf("writing skill: %w", err)
	}

	fmt.Printf("Installed homepki Agent Skill → %s\n", dest)
	fmt.Println("Start a new AI coding session to pick it up.")
	return nil
}

func init() {
	rootCmd.AddCommand(skillCmd)
	skillCmd.AddCommand(skillInstallCmd, skillPathCmd)

	skillInstallCmd.Flags().BoolVar(&skillClaude, "claude", true, "Install into Claude Code's user skills directory (~/.claude/skills/homepki)")
	skillInstallCmd.Flags().BoolVar(&skillPrint, "print", false, "Write the skill to stdout instead of installing")
	skillInstallCmd.Flags().BoolVarP(&skillForce, "force", "f", false, "Overwrite an existing installed skill")
}
