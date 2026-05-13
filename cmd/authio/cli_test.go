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
