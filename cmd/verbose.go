package cmd

import "github.com/cyberark/idsec-sdk-golang/pkg/common"

// cmdLogger is the verbose logging interface for command-level output.
// Satisfied by *common.IdsecLogger.
type cmdLogger interface {
	Info(msg string, v ...interface{})
}

// log is the package-level logger used by commands for verbose output.
// Tests can swap this with a spy. PersistentPreRunE sets IDSEC_LOG_LEVEL
// which controls whether Info() calls produce output.
var log cmdLogger = common.GetLogger("grant", -1)
