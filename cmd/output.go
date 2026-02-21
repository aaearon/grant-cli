package cmd

import (
	"encoding/json"
	"io"
)

// outputFormat holds the global output format flag value.
var outputFormat string

// isJSONOutput returns true when the user has requested JSON output.
func isJSONOutput() bool {
	return outputFormat == "json"
}

// writeJSON encodes data as indented JSON to the given writer.
func writeJSON(w io.Writer, data any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}
