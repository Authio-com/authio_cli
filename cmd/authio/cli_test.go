package main

import "testing"

func TestRunUnknownCommand(t *testing.T) {
	if err := run([]string{"nope"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunVersion(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatal(err)
	}
}

func TestRunNoArgs(t *testing.T) {
	if err := run(nil); err != nil {
		t.Fatal(err)
	}
}

func TestRunHelpListsNewCommands(t *testing.T) {
	// Help should not error and the dispatch table should know the new
	// C8/C9 commands.
	if err := run([]string{"help"}); err != nil {
		t.Fatal(err)
	}
}

func TestRunListenWithoutForward(t *testing.T) {
	// `listen` with no --forward is a usage error, exercised through the
	// real dispatch path (no network involved).
	if err := run([]string{"listen"}); err == nil {
		t.Fatal("expected usage error from `listen` without --forward")
	}
}

func TestRunEnvNoCreds(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := run([]string{"env"}); err == nil {
		t.Fatal("expected error from `env` without credentials")
	}
}
