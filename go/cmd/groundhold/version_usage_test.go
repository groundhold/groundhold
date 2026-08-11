package main

import (
	"strings"
	"testing"
)

// D589. `groundhold version` exists, works, and is named nowhere in the help. Found
// by running the last unexercised commands: `--help` lists fifty verbs and not this
// one, and the drill-down line invites `groundhold <verb> --help` for any of them.
//
// It matters more than its size suggests. This project delivers binaries by hand,
// with a manifest naming a commit — and the first question anyone holding such a
// binary asks is which one they are running. The answer exists and is undiscoverable
// from the tool itself.
//
// Kept narrow deliberately: `--version` and `-v` are conventions a user tries without
// being told, `help` is what they typed to get here. The one worth advertising is the
// spelling a script writes.
func TestVersionIsAdvertisedInTheHelp(t *testing.T) {
	if !strings.Contains(usage, "groundhold version") {
		t.Error("`groundhold version` is a real command and the usage block never " +
			"mentions it — the question every hand-delivered binary provokes has an " +
			"answer the tool does not offer")
	}
}

// And it must still answer. A usage line for a command that stopped working is the
// same defect pointed the other way (D586).
func TestVersionCommandAnswers(t *testing.T) {
	for _, form := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		if code := run(form); code != 0 {
			t.Errorf("%v exited %d — the help now promises this works", form, code)
		}
	}
}
