package cmd

import (
	"fmt"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

// revocationRecord is the reconciled outcome for one *requested* session.
// There is exactly one record per requested session, whether or not the
// service returned a row for it.
type revocationRecord struct {
	SessionID string
	Status    string // raw API value; "" when no row was returned
	Outcome   scamodels.RevocationOutcome
	Reason    string // why this is not a confirmed revocation; "" when revoked
}

// unattributedResult is a returned row that cannot be attributed to a
// requested session: either an ID that was never requested, or an empty ID.
type unattributedResult struct {
	SessionID string
	Status    string
}

// dedupeSessionIDs removes repeated IDs, preserving first-seen order.
func dedupeSessionIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// outcomeRank orders outcomes best to worst so the worst can win when the
// service returns more than one row for the same session.
func outcomeRank(o scamodels.RevocationOutcome) int {
	switch o {
	case scamodels.OutcomeRevoked:
		return 3
	case scamodels.OutcomeInProgress:
		return 2
	case scamodels.OutcomeNotApplicable:
		return 1
	default:
		return 0
	}
}

// reasonForOutcome explains a non-complete outcome in provider-neutral terms.
// It never attributes a cause grant did not observe.
func reasonForOutcome(outcome scamodels.RevocationOutcome, status string) string {
	switch outcome {
	case scamodels.OutcomeRevoked:
		return ""
	case scamodels.OutcomeInProgress:
		return "accepted by the service, not yet confirmed complete"
	case scamodels.OutcomeNotApplicable:
		return "the service reported revocation is not applicable to this session"
	default:
		return fmt.Sprintf("unexpected status %q (treated as failure)", status)
	}
}

// reconcileRevocations joins the service's results onto the *requested* session
// IDs, which are the source of truth. A requested session with no returned row
// is an unknown outcome, not a success. The requested set is deduplicated,
// preserving first-seen order.
func reconcileRevocations(requested []string, results []scamodels.RevocationResult) ([]revocationRecord, []unattributedResult) {
	ids := dedupeSessionIDs(requested)

	index := make(map[string]int, len(ids))
	records := make([]revocationRecord, len(ids))
	for i, id := range ids {
		index[id] = i
		records[i] = revocationRecord{
			SessionID: id,
			Outcome:   scamodels.OutcomeUnknown,
			Reason:    "no result returned by the service for this session",
		}
	}

	seen := make(map[string]bool, len(ids))
	var unattached []unattributedResult

	for _, r := range results {
		i, ok := index[r.SessionID]
		if !ok || r.SessionID == "" {
			unattached = append(unattached, unattributedResult{SessionID: r.SessionID, Status: r.RevocationStatus})
			continue
		}

		outcome := scamodels.ClassifyRevocationStatus(r.RevocationStatus)
		// Worst outcome wins: a later success must never mask an earlier failure.
		if seen[r.SessionID] && outcomeRank(outcome) >= outcomeRank(records[i].Outcome) {
			continue
		}
		seen[r.SessionID] = true

		records[i].Status = r.RevocationStatus
		records[i].Outcome = outcome
		records[i].Reason = reasonForOutcome(outcome, r.RevocationStatus)
	}

	return records, unattached
}

// revocationSummary counts outcomes over the requested session set.
type revocationSummary struct {
	requested  int
	revoked    int
	inProgress int
	failed     int
}

// allAccepted reports whether every requested session was accepted by the
// service, counting OutcomeInProgress as accepted. This is the exit-code
// predicate: see errRevocationIncomplete for the policy and its limits.
// An empty requested set is not a success: nothing was confirmed revoked.
func (s revocationSummary) allAccepted() bool {
	return s.requested > 0 && s.failed == 0
}

func summarizeRevocations(records []revocationRecord) revocationSummary {
	s := revocationSummary{requested: len(records)}
	for _, r := range records {
		switch r.Outcome {
		case scamodels.OutcomeRevoked:
			s.revoked++
		case scamodels.OutcomeInProgress:
			s.inProgress++
		default:
			s.failed++
		}
	}
	return s
}
