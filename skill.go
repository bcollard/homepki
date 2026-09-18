package main

import _ "embed"

// skillMD is the canonical homepki Agent Skill definition, embedded from the
// repo-root SKILL.md. `homepki skill install` ships it inside the binary so the
// installed CLI can drop the skill into an AI coding tool's skills directory
// without a separate download. SKILL.md remains the single source of truth; it
// is handed to the cmd package via cmd.SetSkill, the same way version metadata
// is injected.
//
//go:embed SKILL.md
var skillMD string
