package status

// These are all the current valid states for Red Hat bugs in Jira
const (
	New            = "NEW"
	Backlog        = "BACKLOG"
	Assigned       = "ASSIGNED"
	InProgess      = "IN PROGRESS"
	Modified       = "MODIFIED"
	Post           = "POST"
	OnDev          = "ON_DEV"
	OnQA           = "ON_QA"
	Verified       = "VERIFIED"
	ReleasePending = "RELEASE PENDING"
	Closed         = "CLOSED"
)
