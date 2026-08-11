package main

import "testing"

// D590. D589 ended on the observation that this project had no test that its
// CONVENTIONS still work — the things a user types without being told, which are not
// a wrong answer, not a broken build, and not a claim any document makes. `--version`
// had been broken for eleven hours behind every green gate.
//
// So: the conventions, in one place, exercised. Sweeping them found a second one D567
// had closed on.
//
//	groundhold -- verify ...   ->  unknown flag "--" ... exit 1
//
// `--` is POSIX for "everything after this is positional", and the rule that
// refuses an unrecognised token starting with "-" refused it too. Nobody had typed
// it here, which is the point: a convention is what someone reaches for when the
// documentation is not in front of them.
func TestConventionsThatUsersTryUnprompted(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"--help", []string{"--help"}},
		{"-h", []string{"-h"}},
		{"help", []string{"help"}},
		{"help <verb>", []string{"help", "verify"}},
		{"version", []string{"version"}},
		{"--version", []string{"--version"}},
		{"-v", []string{"-v"}},
		{"-- ends the flags", []string{"--", "version"}},
	} {
		if code := run(tc.args); code != 0 {
			t.Errorf("%s exited %d — a convention a user reaches for without reading "+
				"anything", tc.name, code)
		}
	}
}

// The separator must not become a way to smuggle an unknown flag past D567: after
// `--` everything is positional, so a bogus VERB is still a usage error.
func TestSeparatorDoesNotDisableTheUnknownFlagGuard(t *testing.T) {
	if code := run([]string{"--", "__not_a_verb__"}); code == 0 {
		t.Error("`-- __not_a_verb__` was accepted — the separator turned off the " +
			"guard rather than ending the flags")
	}
	if code := run([]string{"posture", "--not-a-flag", "x"}); code == 0 {
		t.Error("an unknown flag without a separator was accepted (D567 regression)")
	}
}
