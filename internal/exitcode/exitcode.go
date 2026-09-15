// Package exitcode defines the shared QYVORA process exit-code contract.
//
//	0   success
//	1   runtime failure (collection error, I/O error, internal error)
//	2   usage error (unknown flag/command, invalid value, missing/invalid target)
//	130 interrupted (128 + SIGINT)
//
// Automation distinguishes these without parsing human output.
package exitcode

const (
	Success     = 0
	Runtime     = 1
	Usage       = 2
	Interrupted = 130
)
