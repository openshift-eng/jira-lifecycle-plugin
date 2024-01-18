package helpers

import (
	"testing"

	"github.com/andygrunwald/go-jira"
	"github.com/google/go-cmp/cmp"
)

func TestGetActiveSprintIDs(t *testing.T) {
	t.Parallel()
	active1 := "com.atlassian.greenhopper.service.sprint.Sprint@11b54434[id=57955,rapidViewId=14885,state=ACTIVE,name=uShift Sprint 248,startDate=2024-01-15T09:00:00.000Z,endDate=2024-02-05T09:00:00.000Z,completeDate=<null>,activatedDate=2024-01-15T08:17:37.677Z,sequence=57955,goal=,autoStartStop=false,synced=false]"
	closed1 := "com.atlassian.greenhopper.service.sprint.Sprint@57a3e8ba[id=57484,rapidViewId=14885,state=CLOSED,name=uShift Sprint 247,startDate=2023-12-25T17:07:00.000Z,endDate=2024-01-15T17:07:00.000Z,completeDate=2024-01-15T08:15:40.614Z,activatedDate=2023-12-25T14:11:56.948Z,sequence=57484,goal=,autoStartStop=false,synced=false]"
	closed2 := "com.atlassian.greenhopper.service.sprint.Sprint@21c6823a[id=57540,rapidViewId=5254,state=CLOSED,name=SDN Sprint 247,startDate=2023-12-25T08:00:00.000Z,endDate=2024-01-13T08:00:00.000Z,completeDate=2024-01-15T10:54:35.488Z,activatedDate=2024-01-08T11:20:24.310Z,sequence=57540,goal=,autoStartStop=false,synced=false]"
	var testCases = []struct {
		name     string
		issue    interface{}
		expected int
	}{{
		name:     "Empty",
		expected: -1,
	}, {
		name:     "One active, one closed",
		issue:    []interface{}{closed1, active1},
		expected: 57955,
	}, {
		name:     "Two closed",
		issue:    []interface{}{closed1, closed2},
		expected: -1,
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			updates, err := GetActiveSprintID(tc.issue)
			if err != nil {
				t.Errorf("Received error when none were expected: %v", err)
			}
			if diff := cmp.Diff(updates, tc.expected, cmp.AllowUnexported(jira.Date{})); diff != "" {
				t.Errorf("Expected results do not match: %s", diff)
			}
		})
	}
}
