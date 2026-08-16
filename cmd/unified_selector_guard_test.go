package cmd

import (
	"errors"
	"testing"

	"github.com/aaearon/grant-cli/internal/ui"
)

// TestUIUnifiedSelector_EmptyItemsGuard pins the two entry guards on
// uiUnifiedSelector.SelectItem, including the order they run in.
//
// The empty-items guard used to have an equivalent in ui.SelectGroup; PR #68
// deleted that function as dead code and its test went with it, leaving this
// guard unpinned. Note the message is "available", which is what distinguishes
// it from the earlier "...found, check your SCA policies" guard in
// resolveUnifiedSelection — asserting the exact string keeps the two apart.
//
// Not parallel: mutates the package-global ui.IsTerminalFunc via
// withInteractiveTTY.
func TestUIUnifiedSelector_EmptyItemsGuard(t *testing.T) {
	const wantEmptyMsg = "no eligible targets or groups available"

	t.Run("interactive with no items returns the empty-items error", func(t *testing.T) {
		withInteractiveTTY(t, true)
		withDiscardedStdout(t)

		selector := &uiUnifiedSelector{}
		got, err := selector.SelectItem(nil)
		if err == nil {
			t.Fatalf("SelectItem(nil) returned no error (got item %+v); the len(items)==0 guard is missing", got)
		}
		if got != nil {
			t.Errorf("SelectItem(nil) returned item %+v, want nil", got)
		}
		if err.Error() != wantEmptyMsg {
			t.Errorf("SelectItem(nil) error = %q, want exactly %q", err.Error(), wantEmptyMsg)
		}
		if errors.Is(err, ui.ErrNotInteractive) {
			t.Errorf("SelectItem(nil) in a TTY wrapped ui.ErrNotInteractive: %v", err)
		}
	})

	t.Run("interactive with empty slice returns the empty-items error", func(t *testing.T) {
		withInteractiveTTY(t, true)
		withDiscardedStdout(t)

		selector := &uiUnifiedSelector{}
		_, err := selector.SelectItem([]selectionItem{})
		if err == nil {
			t.Fatal("SelectItem([]) returned no error; the len(items)==0 guard is missing")
		}
		if err.Error() != wantEmptyMsg {
			t.Errorf("SelectItem([]) error = %q, want exactly %q", err.Error(), wantEmptyMsg)
		}
	})

	// Guard order: the interactivity check must run first. With the guards
	// swapped, a non-interactive caller with nothing eligible would be told
	// "no eligible targets" instead of being pointed at the non-interactive
	// flags, which is the wrong remedy.
	t.Run("non-interactive with no items reports non-interactive, not empty", func(t *testing.T) {
		withInteractiveTTY(t, false)

		selector := &uiUnifiedSelector{}
		_, err := selector.SelectItem(nil)
		if err == nil {
			t.Fatal("SelectItem(nil) when non-interactive returned no error")
		}
		if !errors.Is(err, ui.ErrNotInteractive) {
			t.Errorf("SelectItem(nil) when non-interactive = %v, want ui.ErrNotInteractive (guards may be in the wrong order)", err)
		}
		if err.Error() == wantEmptyMsg {
			t.Errorf("SelectItem(nil) when non-interactive returned the empty-items error %q; the interactivity guard must run first", err.Error())
		}
	})
}
