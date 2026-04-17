package helpers

import (
	"testing"
	"time"

	"github.com/andygrunwald/go-jira"
	"github.com/google/go-cmp/cmp"
)

func TestGetActiveSprintIDs(t *testing.T) {
	t.Parallel()

	active1 := jira.Sprint{
		ID:        57955,
		Name:      "uShift Sprint 248",
		EndDate:   TimePtr(time.Date(2024, 2, 5, 9, 0, 0, 0, time.UTC)),
		StartDate: TimePtr(time.Date(2024, 1, 15, 9, 0, 0, 0, time.UTC)),
		State:     "active",
	}
	closed1 := jira.Sprint{
		ID:           57484,
		Name:         "uShift Sprint 247",
		EndDate:      TimePtr(time.Date(2024, 1, 15, 17, 7, 0, 0, time.UTC)),
		StartDate:    TimePtr(time.Date(2023, 12, 25, 17, 7, 0, 0, time.UTC)),
		CompleteDate: TimePtr(time.Date(2024, 1, 15, 8, 15, 40, 614, time.UTC)),
		State:        "closed",
	}
	closed2 := jira.Sprint{
		ID:           57484,
		Name:         "uShift Sprint 247",
		EndDate:      TimePtr(time.Date(2024, 1, 13, 8, 0, 0, 0, time.UTC)),
		StartDate:    TimePtr(time.Date(2023, 12, 25, 8, 0, 0, 0, time.UTC)),
		CompleteDate: TimePtr(time.Date(2024, 1, 15, 10, 54, 35, 488, time.UTC)),
		State:        "closed",
	}
	var testCases = []struct {
		name     string
		sprints  []jira.Sprint
		expected int
	}{{
		name:     "Empty",
		expected: -1,
	}, {
		name:     "One active, one closed",
		sprints:  []jira.Sprint{closed1, active1},
		expected: 57955,
	}, {
		name:     "Two closed",
		sprints:  []jira.Sprint{closed1, closed2},
		expected: -1,
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			updates, err := GetActiveSprintID(tc.sprints)
			if err != nil {
				t.Errorf("Received error when none were expected: %v", err)
			}
			if diff := cmp.Diff(updates, tc.expected, cmp.AllowUnexported(jira.Date{})); diff != "" {
				t.Errorf("Expected results do not match: %s", diff)
			}
		})
	}
}
