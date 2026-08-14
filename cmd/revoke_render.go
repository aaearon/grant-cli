package cmd

import (
	"fmt"
	"io"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

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

// summaryLine states the outcome over the *requested* sessions, keeping
// confirmed revocations separate from ones merely accepted. It never claims
// that an accepted revocation is a finished one.
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
func renderRevocationResults(w io.Writer, records []revocationRecord, unattached []unattributedResult) {
	for _, r := range records {
		fmt.Fprintf(w, "  %s: %s\n", r.SessionID, describeRecord(r))
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
			Reason:    r.Reason,
		})
	}
	for _, u := range unattached {
		// The outcome is always unknown, whatever the raw status says: a row
		// grant never asked for is not a success by any reading. The raw
		// status is preserved for the operator.
		out = append(out, revocationOutput{
			SessionID:  u.SessionID,
			Status:     u.Status,
			Outcome:    string(scamodels.OutcomeUnknown),
			Reason:     "result was not requested and satisfies no requested session",
			Unexpected: true,
		})
	}
	return out
}
