package cmd

import (
	"fmt"
	"io"
	"time"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

// expiryHinter supplies the best-effort "expires in ~Xm" note. The hint needs
// both session metadata (for the duration) and a local elevation timestamp, so
// it is unavailable in direct mode, where grant only has bare session IDs.
//
// The note is purely informational. It never explains *why* a revocation was
// refused — grant has no evidence for that.
type expiryHinter struct {
	metadata   map[string]scamodels.SessionInfo
	timestamps map[string]time.Time
	now        func() time.Time
}

// note returns a parenthesised expiry clause, or "" when it is unknown.
func (h expiryHinter) note(sessionID string) string {
	if h.now == nil || len(h.metadata) == 0 || len(h.timestamps) == 0 {
		return ""
	}
	session, ok := h.metadata[sessionID]
	if !ok {
		return ""
	}
	remaining, ok := computeRemainingTimeAt([]scamodels.SessionInfo{session}, h.timestamps, h.now())[sessionID]
	if !ok {
		return ""
	}
	if remaining <= 0 {
		return " (this session has already expired)"
	}
	totalMin := int(remaining.Minutes())
	if totalMin >= 60 {
		return fmt.Sprintf(" (this session expires in ~%dh %dm)", totalMin/60, totalMin%60)
	}
	return fmt.Sprintf(" (this session expires in ~%dm)", totalMin)
}

// describeRecord renders one reconciled record as a human-readable line body.
func describeRecord(r revocationRecord) string {
	switch r.Outcome {
	case scamodels.OutcomeRevoked:
		return fmt.Sprintf("revoked (%s)", r.Status)
	case scamodels.OutcomeInProgress:
		return fmt.Sprintf("revocation in progress — %s (%s)", r.Reason, r.Status)
	case scamodels.OutcomeNotApplicable:
		return fmt.Sprintf("NOT revoked — %s (%s)", r.Reason, r.Status)
	default:
		return "NOT revoked — " + r.Reason
	}
}

// summaryLine states the outcome over the *requested* sessions, keeping the
// accepted-versus-complete distinction visible. It never claims that an
// accepted revocation is a finished one.
func summaryLine(s revocationSummary) string {
	line := fmt.Sprintf("%d of %d requested sessions revoked", s.revoked, s.requested)
	if s.inProgress > 0 {
		line += fmt.Sprintf("; %d %s in progress", s.inProgress, plural(s.inProgress, "revocation", "revocations"))
	}
	if s.failed > 0 {
		line += fmt.Sprintf("; %d not revoked", s.failed)
	}
	return line + "."
}

func plural(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// renderRevocationResults prints the full per-session breakdown. It is always
// called before the command returns its error, so a non-zero exit is never
// opaque.
func renderRevocationResults(w io.Writer, records []revocationRecord, unattached []unattributedResult, hints expiryHinter) {
	for _, r := range records {
		fmt.Fprintf(w, "  %s: %s%s\n", r.SessionID, describeRecord(r), hints.note(r.SessionID))
	}

	for _, u := range unattached {
		if u.SessionID == "" {
			fmt.Fprintf(w, "  ! unexpected result with an empty session ID (status %q); it cannot be attributed to any requested session\n", u.Status)
			continue
		}
		fmt.Fprintf(w, "  ! unexpected result for session %s (status %q); it was not requested and satisfies nothing\n", u.SessionID, u.Status)
	}

	if len(records) > 0 {
		fmt.Fprintf(w, "%s\n", summaryLine(summarizeRevocations(records)))
	}
}

// buildRevocationJSON builds the machine-readable output: one entry per
// requested session in requested order, followed by unattributable results.
func buildRevocationJSON(records []revocationRecord, unattached []unattributedResult) []revocationOutput {
	out := make([]revocationOutput, 0, len(records)+len(unattached))
	for _, r := range records {
		out = append(out, revocationOutput{
			SessionID: r.SessionID,
			Status:    r.Status,
			Outcome:   string(r.Outcome),
			Accepted:  r.Outcome.Accepted(),
			Complete:  r.Outcome.Complete(),
			Reason:    r.Reason,
		})
	}
	for _, u := range unattached {
		outcome := scamodels.ClassifyRevocationStatus(u.Status)
		out = append(out, revocationOutput{
			SessionID:  u.SessionID,
			Status:     u.Status,
			Outcome:    string(outcome),
			Accepted:   false,
			Complete:   false,
			Reason:     "result was not requested and satisfies no requested session",
			Unexpected: true,
		})
	}
	return out
}
