package passport

// CheckStatus is the outcome of one check run by the gateway or a verifier.
type CheckStatus string

// Check outcomes.
const (
	CheckOK      CheckStatus = "ok"
	CheckFailed  CheckStatus = "fail"
	CheckSkipped CheckStatus = "skipped"
)

// Check is one check with its outcome.
type Check struct {
	Key    string
	Status CheckStatus
	Err    error
}

// CheckRun executes a fixed sequence of named checks and records their
// outcomes. It stops at the first failure and reports the rest as skipped, so
// a caller always gets one entry per check in the documented order. Both the
// input gateway and the verifier report their checks this way.
type CheckRun struct {
	checks []Check
	err    error
}

// Do runs the next check unless an earlier one already failed.
func (r *CheckRun) Do(key string, fn func() error) {
	if r.err != nil {
		r.checks = append(r.checks, Check{Key: key, Status: CheckSkipped})
		return
	}
	if err := fn(); err != nil {
		r.err = err
		r.checks = append(r.checks, Check{Key: key, Status: CheckFailed, Err: err})
		return
	}
	r.checks = append(r.checks, Check{Key: key, Status: CheckOK})
}

// Checks returns one entry per check, in the order they were run.
func (r *CheckRun) Checks() []Check { return r.checks }

// Err returns the failure that stopped the run, or nil if every check passed.
func (r *CheckRun) Err() error { return r.err }
