package main

import "github.com/bcollard/homepki/cmd"

// Injected at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersion(version, commit, date)
	cmd.SetSkill(skillMD)
	cmd.Execute()
}
