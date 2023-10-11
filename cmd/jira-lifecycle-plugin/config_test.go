package main

import (
	"reflect"
	"testing"

	"k8s.io/utils/diff"
	"sigs.k8s.io/yaml"
)

func TestJiraOptionsForItem(t *testing.T) {
	open := true
	one, two := "v1", "v2"
	var testCases = []struct {
		name     string
		item     string
		config   map[string]JiraBranchOptions
		expected JiraBranchOptions
	}{
		{
			name:     "no config means no options",
			item:     "item",
			config:   map[string]JiraBranchOptions{},
			expected: JiraBranchOptions{},
		},
		{
			name:     "unrelated config means no options",
			item:     "item",
			config:   map[string]JiraBranchOptions{"other": {IsOpen: &open, TargetVersion: &one}},
			expected: JiraBranchOptions{},
		},
		{
			name:     "global config resolves to options",
			item:     "item",
			config:   map[string]JiraBranchOptions{"*": {IsOpen: &open, TargetVersion: &one}},
			expected: JiraBranchOptions{IsOpen: &open, TargetVersion: &one},
		},
		{
			name:     "specific config resolves to options",
			item:     "item",
			config:   map[string]JiraBranchOptions{"item": {IsOpen: &open, TargetVersion: &one}},
			expected: JiraBranchOptions{IsOpen: &open, TargetVersion: &one},
		},
		{
			name: "global and specific config resolves to options that favor specificity",
			item: "item",
			config: map[string]JiraBranchOptions{
				"*":    {IsOpen: &open, TargetVersion: &one},
				"item": {TargetVersion: &two},
			},
			expected: JiraBranchOptions{IsOpen: &open, TargetVersion: &two},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if actual, expected := JiraOptionsForItem(testCase.item, testCase.config), testCase.expected; !reflect.DeepEqual(actual, expected) {
				t.Errorf("%s: got incorrect options for item %q: %v", testCase.name, testCase.item, diff.ObjectReflectDiff(actual, expected))
			}
		})
	}
}

func TestResolveJiraOptions(t *testing.T) {
	open, closed := true, false
	yes, no := true, false
	one, two := "v1", "v2"
	modified, verified, post, pre, post2, pre2 := "MODIFIED", "VERIFIED", "POST", "PRE", "POST2", "PRE2"
	modifiedState := JiraBugState{Status: modified}
	verifiedState := JiraBugState{Status: verified}
	postState := JiraBugState{Status: post}
	preState := JiraBugState{Status: pre}
	post2State := JiraBugState{Status: post2}
	pre2State := JiraBugState{Status: pre2}
	var testCases = []struct {
		name          string
		parent, child JiraBranchOptions
		expected      JiraBranchOptions
	}{
		{
			name: "no parent or child means no output",
		},
		{
			name:   "no child means a copy of parent is the output",
			parent: JiraBranchOptions{ValidateByDefault: &yes, IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, DependentBugStates: &[]JiraBugState{verifiedState}, DependentBugTargetVersions: &[]string{one}, StateAfterValidation: &postState},
			expected: JiraBranchOptions{
				ValidateByDefault:          &yes,
				IsOpen:                     &open,
				TargetVersion:              &one,
				ValidStates:                &[]JiraBugState{modifiedState},
				DependentBugStates:         &[]JiraBugState{verifiedState},
				DependentBugTargetVersions: &[]string{one},
				StateAfterValidation:       &postState,
			},
		},
		{
			name:  "no parent means a copy of child is the output",
			child: JiraBranchOptions{ValidateByDefault: &yes, IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, DependentBugStates: &[]JiraBugState{verifiedState}, DependentBugTargetVersions: &[]string{one}, StateAfterValidation: &postState},
			expected: JiraBranchOptions{
				ValidateByDefault:          &yes,
				IsOpen:                     &open,
				TargetVersion:              &one,
				ValidStates:                &[]JiraBugState{modifiedState},
				DependentBugStates:         &[]JiraBugState{verifiedState},
				DependentBugTargetVersions: &[]string{one},
				StateAfterValidation:       &postState,
			},
		},
		{
			name:     "child overrides parent on IsOpen",
			parent:   JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState},
			child:    JiraBranchOptions{IsOpen: &closed},
			expected: JiraBranchOptions{IsOpen: &closed, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState},
		},
		{
			name:     "child overrides parent on target release",
			parent:   JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState},
			child:    JiraBranchOptions{TargetVersion: &two},
			expected: JiraBranchOptions{IsOpen: &open, TargetVersion: &two, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState},
		},
		{
			name:     "child overrides parent on skip target release check",
			parent:   JiraBranchOptions{IsOpen: &open, SkipTargetVersionCheck: &yes, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState},
			child:    JiraBranchOptions{SkipTargetVersionCheck: &no, TargetVersion: &two},
			expected: JiraBranchOptions{IsOpen: &open, SkipTargetVersionCheck: &no, TargetVersion: &two, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState},
		},
		{
			name:     "child overrides parent on states",
			parent:   JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState},
			child:    JiraBranchOptions{ValidStates: &[]JiraBugState{verifiedState}},
			expected: JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{verifiedState}, StateAfterValidation: &postState},
		},
		{
			name:     "child overrides parent on state after validation",
			parent:   JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState},
			child:    JiraBranchOptions{StateAfterValidation: &preState},
			expected: JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &preState},
		},
		{
			name:     "child overrides parent on premerge state after validation",
			parent:   JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState, PreMergeStateAfterValidation: &post2State},
			child:    JiraBranchOptions{StateAfterValidation: &preState, PreMergeStateAfterValidation: &pre2State},
			expected: JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &preState, PreMergeStateAfterValidation: &pre2State},
		},
		{
			name:     "child overrides parent on validation by default",
			parent:   JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState},
			child:    JiraBranchOptions{ValidateByDefault: &yes},
			expected: JiraBranchOptions{ValidateByDefault: &yes, IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState},
		},
		{
			name:   "child overrides parent on dependent bug states",
			parent: JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, DependentBugStates: &[]JiraBugState{verifiedState}, StateAfterValidation: &postState},
			child:  JiraBranchOptions{DependentBugStates: &[]JiraBugState{modifiedState}},
			expected: JiraBranchOptions{
				IsOpen:               &open,
				TargetVersion:        &one,
				ValidStates:          &[]JiraBugState{modifiedState},
				DependentBugStates:   &[]JiraBugState{modifiedState},
				StateAfterValidation: &postState,
			},
		},
		{
			name:     "child overrides parent on dependent bug target releases",
			parent:   JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState, DependentBugTargetVersions: &[]string{one}},
			child:    JiraBranchOptions{DependentBugTargetVersions: &[]string{two}},
			expected: JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState, DependentBugTargetVersions: &[]string{two}},
		},
		{
			name:   "child overrides parent on state after merge",
			parent: JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState, StateAfterMerge: &postState},
			child:  JiraBranchOptions{StateAfterMerge: &preState},
			expected: JiraBranchOptions{
				IsOpen:               &open,
				TargetVersion:        &one,
				ValidStates:          &[]JiraBugState{modifiedState},
				StateAfterValidation: &postState,
				StateAfterMerge:      &preState,
			},
		},
		{
			name:   "child overrides parent on premerge state after merge",
			parent: JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState, StateAfterMerge: &postState, PreMergeStateAfterMerge: &postState},
			child:  JiraBranchOptions{StateAfterMerge: &preState, PreMergeStateAfterMerge: &pre2State},
			expected: JiraBranchOptions{
				IsOpen:                  &open,
				TargetVersion:           &one,
				ValidStates:             &[]JiraBugState{modifiedState},
				StateAfterValidation:    &postState,
				StateAfterMerge:         &preState,
				PreMergeStateAfterMerge: &pre2State,
			},
		},
		{
			name:   "child overrides parent on state after close",
			parent: JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState, StateAfterMerge: &postState, StateAfterClose: &postState},
			child:  JiraBranchOptions{StateAfterClose: &preState},
			expected: JiraBranchOptions{
				IsOpen:               &open,
				TargetVersion:        &one,
				ValidStates:          &[]JiraBugState{modifiedState},
				StateAfterValidation: &postState,
				StateAfterMerge:      &postState,
				StateAfterClose:      &preState,
			},
		},
		{
			name:   "child overrides parent on premerge state after close",
			parent: JiraBranchOptions{IsOpen: &open, TargetVersion: &one, ValidStates: &[]JiraBugState{modifiedState}, StateAfterValidation: &postState, StateAfterMerge: &postState, StateAfterClose: &postState, PreMergeStateAfterClose: &post2State},
			child:  JiraBranchOptions{StateAfterClose: &preState, PreMergeStateAfterClose: &pre2State},
			expected: JiraBranchOptions{
				IsOpen:                  &open,
				TargetVersion:           &one,
				ValidStates:             &[]JiraBugState{modifiedState},
				StateAfterValidation:    &postState,
				StateAfterMerge:         &postState,
				StateAfterClose:         &preState,
				PreMergeStateAfterClose: &pre2State,
			},
		},
		{
			name:   "child overrides parent on all fields",
			parent: JiraBranchOptions{ValidateByDefault: &yes, IsOpen: &open, SkipTargetVersionCheck: &yes, TargetVersion: &one, ValidStates: &[]JiraBugState{verifiedState}, DependentBugStates: &[]JiraBugState{verifiedState}, DependentBugTargetVersions: &[]string{one}, StateAfterValidation: &postState, StateAfterMerge: &postState},
			child:  JiraBranchOptions{ValidateByDefault: &no, IsOpen: &closed, SkipTargetVersionCheck: &no, TargetVersion: &two, ValidStates: &[]JiraBugState{modifiedState}, DependentBugStates: &[]JiraBugState{modifiedState}, DependentBugTargetVersions: &[]string{two}, StateAfterValidation: &preState, StateAfterMerge: &preState},
			expected: JiraBranchOptions{
				ValidateByDefault:          &no,
				IsOpen:                     &closed,
				SkipTargetVersionCheck:     &no,
				TargetVersion:              &two,
				ValidStates:                &[]JiraBugState{modifiedState},
				DependentBugStates:         &[]JiraBugState{modifiedState},
				DependentBugTargetVersions: &[]string{two},
				StateAfterValidation:       &preState,
				StateAfterMerge:            &preState,
			},
		},
		{
			name:     "parent target release is excluded on child",
			parent:   JiraBranchOptions{TargetVersion: &one},
			child:    JiraBranchOptions{ExcludeDefaults: &yes},
			expected: JiraBranchOptions{ExcludeDefaults: &yes},
		},
		{
			name:     "parent target release is excluded on child with other options",
			parent:   JiraBranchOptions{DependentBugTargetVersions: &[]string{one}},
			child:    JiraBranchOptions{TargetVersion: &one, ExcludeDefaults: &yes},
			expected: JiraBranchOptions{TargetVersion: &one, ExcludeDefaults: &yes},
		},
		{
			name:     "parent exclude merges with child options",
			parent:   JiraBranchOptions{DependentBugTargetVersions: &[]string{one}, ExcludeDefaults: &yes},
			child:    JiraBranchOptions{TargetVersion: &one},
			expected: JiraBranchOptions{DependentBugTargetVersions: &[]string{one}, TargetVersion: &one, ExcludeDefaults: &yes},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if actual, expected := ResolveJiraOptions(testCase.parent, testCase.child), testCase.expected; !reflect.DeepEqual(actual, expected) {
				t.Errorf("%s: resolved incorrect options for parent and child: %v", testCase.name, diff.ObjectReflectDiff(actual, expected))
			}
		})
	}
}

func TestJiraOptionsForBranch(t *testing.T) {
	open, closed := true, false
	yes, no := true, false
	globalDefault, globalBranchDefault, orgDefault, orgBranchDefault, repoDefault, repoBranch := "global-default", "global-branch-default", "my-org-default", "my-org-branch-default", "my-repo-default", "my-repo-branch"
	post, pre, release, notabug, new, reset := "POST", "PRE", "RELEASE_PENDING", "NOTABUG", "NEW", "RESET"
	verifiedState, modifiedState := JiraBugState{Status: "VERIFIED"}, JiraBugState{Status: "MODIFIED"}
	postState, preState, releaseState, notabugState, newState, resetState := JiraBugState{Status: post}, JiraBugState{Status: pre}, JiraBugState{Status: release}, JiraBugState{Status: notabug}, JiraBugState{Status: new}, JiraBugState{Status: reset}
	closedErrata := JiraBugState{Status: "CLOSED", Resolution: "ERRATA"}
	orgAllowedSecurityLevels, repoAllowedSecurityLevels := []string{"test"}, []string{"security", "test"}

	rawConfig := `default:
  "*":
    target_version: global-default
  "global-branch":
    is_open: false
    target_version: global-branch-default
orgs:
  my-org:
    default:
      "*":
        is_open: true
        target_version: my-org-default
        state_after_validation:
          status: "PRE"
        state_after_close:
          status: "NEW"
        allowed_security_levels:
        - test
      "my-org-branch":
        target_version: my-org-branch-default
        state_after_validation:
          status: "POST"
    repos:
      my-repo:
        branches:
          "*":
            is_open: false
            target_version: my-repo-default
            valid_states:
            - status: VERIFIED
            validate_by_default: false
            state_after_merge:
              status: RELEASE_PENDING
          "my-repo-branch":
            target_version: my-repo-branch
            valid_states:
            - status: MODIFIED
            - status: CLOSED
              resolution: ERRATA
            validate_by_default: true
            state_after_merge:
              status: NOTABUG
            state_after_close:
              status: RESET
            allowed_security_levels:
            - security
          "my-special-branch":
            exclude_defaults: true
            validate_by_default: false
      another-repo:
        branches:
          "*":
            exclude_defaults: true
          "my-org-branch":
            target_version: my-repo-branch`
	var config Config
	if err := yaml.Unmarshal([]byte(rawConfig), &config); err != nil {
		t.Fatalf("couldn't unmarshal config: %v", err)
	}

	var testCases = []struct {
		name              string
		org, repo, branch string
		expected          JiraBranchOptions
	}{
		{
			name:     "unconfigured branch gets global default",
			org:      "some-org",
			repo:     "some-repo",
			branch:   "some-branch",
			expected: JiraBranchOptions{TargetVersion: &globalDefault},
		},
		{
			name:     "branch on unconfigured org/repo gets global default",
			org:      "some-org",
			repo:     "some-repo",
			branch:   "global-branch",
			expected: JiraBranchOptions{IsOpen: &closed, TargetVersion: &globalBranchDefault},
		},
		{
			name:     "branch on configured org but not repo gets org default",
			org:      "my-org",
			repo:     "some-repo",
			branch:   "some-branch",
			expected: JiraBranchOptions{IsOpen: &open, TargetVersion: &orgDefault, StateAfterValidation: &preState, AllowedSecurityLevels: orgAllowedSecurityLevels, StateAfterClose: &newState},
		},
		{
			name:     "branch on configured org but not repo gets org branch default",
			org:      "my-org",
			repo:     "some-repo",
			branch:   "my-org-branch",
			expected: JiraBranchOptions{IsOpen: &open, TargetVersion: &orgBranchDefault, StateAfterValidation: &postState, AllowedSecurityLevels: orgAllowedSecurityLevels, StateAfterClose: &newState},
		},
		{
			name:     "branch on configured org and repo gets repo default",
			org:      "my-org",
			repo:     "my-repo",
			branch:   "some-branch",
			expected: JiraBranchOptions{ValidateByDefault: &no, IsOpen: &closed, TargetVersion: &repoDefault, ValidStates: &[]JiraBugState{verifiedState}, StateAfterValidation: &preState, StateAfterMerge: &releaseState, AllowedSecurityLevels: orgAllowedSecurityLevels, StateAfterClose: &newState},
		},
		{
			name:     "branch on configured org and repo gets branch config",
			org:      "my-org",
			repo:     "my-repo",
			branch:   "my-repo-branch",
			expected: JiraBranchOptions{ValidateByDefault: &yes, IsOpen: &closed, TargetVersion: &repoBranch, ValidStates: &[]JiraBugState{modifiedState, closedErrata}, StateAfterValidation: &preState, StateAfterMerge: &notabugState, AllowedSecurityLevels: repoAllowedSecurityLevels, StateAfterClose: &resetState},
		},
		{
			name:     "exclude branch on configured org and repo gets branch config",
			org:      "my-org",
			repo:     "my-repo",
			branch:   "my-special-branch",
			expected: JiraBranchOptions{ValidateByDefault: &no, ExcludeDefaults: &yes},
		},
		{
			name:     "exclude branch on repo cascades to branch config",
			org:      "my-org",
			repo:     "another-repo",
			branch:   "my-org-branch",
			expected: JiraBranchOptions{TargetVersion: &repoBranch, ExcludeDefaults: &yes},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if actual, expected := config.OptionsForBranch(testCase.org, testCase.repo, testCase.branch), testCase.expected; !reflect.DeepEqual(actual, expected) {
				t.Errorf("%s: resolved incorrect options for %s/%s#%s: %v", testCase.name, testCase.org, testCase.repo, testCase.branch, diff.ObjectReflectDiff(actual, expected))
			}
		})
	}

	var repoTestCases = []struct {
		name      string
		org, repo string
		expected  map[string]JiraBranchOptions
	}{
		{
			name: "unconfigured repo gets global default",
			org:  "some-org",
			repo: "some-repo",
			expected: map[string]JiraBranchOptions{
				"*":             {TargetVersion: &globalDefault},
				"global-branch": {IsOpen: &closed, TargetVersion: &globalBranchDefault},
			},
		},
		{
			name: "repo in configured org gets org default",
			org:  "my-org",
			repo: "some-repo",
			expected: map[string]JiraBranchOptions{
				"*":             {IsOpen: &open, TargetVersion: &orgDefault, StateAfterValidation: &preState, AllowedSecurityLevels: orgAllowedSecurityLevels, StateAfterClose: &newState},
				"my-org-branch": {IsOpen: &open, TargetVersion: &orgBranchDefault, StateAfterValidation: &postState, AllowedSecurityLevels: orgAllowedSecurityLevels, StateAfterClose: &newState},
			},
		},
		{
			name: "configured repo gets repo config",
			org:  "my-org",
			repo: "my-repo",
			expected: map[string]JiraBranchOptions{
				"*": {
					ValidateByDefault:     &no,
					IsOpen:                &closed,
					TargetVersion:         &repoDefault,
					ValidStates:           &[]JiraBugState{verifiedState},
					StateAfterValidation:  &preState,
					StateAfterMerge:       &releaseState,
					AllowedSecurityLevels: orgAllowedSecurityLevels,
					StateAfterClose:       &newState,
				},
				"my-repo-branch": {
					ValidateByDefault:     &yes,
					IsOpen:                &closed,
					TargetVersion:         &repoBranch,
					ValidStates:           &[]JiraBugState{modifiedState, closedErrata},
					StateAfterValidation:  &preState,
					StateAfterMerge:       &notabugState,
					AllowedSecurityLevels: repoAllowedSecurityLevels,
					StateAfterClose:       &resetState,
				},
				"my-org-branch": {
					ValidateByDefault:     &no,
					IsOpen:                &closed,
					TargetVersion:         &repoDefault,
					ValidStates:           &[]JiraBugState{verifiedState},
					StateAfterValidation:  &postState,
					StateAfterMerge:       &releaseState,
					AllowedSecurityLevels: orgAllowedSecurityLevels,
					StateAfterClose:       &newState,
				},
				"my-special-branch": {
					ValidateByDefault: &no,
					ExcludeDefaults:   &yes,
				},
			},
		},
		{
			name: "excluded repo gets no defaults",
			org:  "my-org",
			repo: "another-repo",
			expected: map[string]JiraBranchOptions{
				"*":             {ExcludeDefaults: &yes},
				"my-org-branch": {ExcludeDefaults: &yes, TargetVersion: &repoBranch},
			},
		},
	}
	for _, testCase := range repoTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			if actual, expected := config.OptionsForRepo(testCase.org, testCase.repo), testCase.expected; !reflect.DeepEqual(actual, expected) {
				t.Errorf("%s: resolved incorrect options for %s/%s: %v", testCase.name, testCase.org, testCase.repo, diff.ObjectReflectDiff(actual, expected))
			}
		})
	}
}

func TestJiraBugState_String(t *testing.T) {
	testCases := []struct {
		name     string
		state    *JiraBugState
		expected string
	}{
		{
			name:     "empty struct",
			state:    &JiraBugState{},
			expected: "",
		},
		{
			name:     "only status",
			state:    &JiraBugState{Status: "CLOSED"},
			expected: "CLOSED",
		},
		{
			name:     "only resolution",
			state:    &JiraBugState{Resolution: "NOTABUG"},
			expected: "any status with resolution NOTABUG",
		},
		{
			name:     "status and resolution",
			state:    &JiraBugState{Status: "CLOSED", Resolution: "NOTABUG"},
			expected: "CLOSED (NOTABUG)",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.state.String()
			if actual != tc.expected {
				t.Errorf("%s: expected %q, got %q", tc.name, tc.expected, actual)
			}
		})
	}
}

func TestJiraBugStateSet_Has(t *testing.T) {
	bugInProgress := JiraBugState{Status: "MODIFIED"}
	bugErrata := JiraBugState{Status: "CLOSED", Resolution: "ERRATA"}
	bugWontfix := JiraBugState{Status: "CLOSED", Resolution: "WONTFIX"}

	testCases := []struct {
		name   string
		states []JiraBugState
		state  JiraBugState

		expectedLength int
		expectedHas    bool
	}{
		{
			name:           "empty set",
			state:          bugInProgress,
			expectedLength: 0,
			expectedHas:    false,
		},
		{
			name:           "membership",
			states:         []JiraBugState{bugInProgress},
			state:          bugInProgress,
			expectedLength: 1,
			expectedHas:    true,
		},
		{
			name:           "non-membership",
			states:         []JiraBugState{bugInProgress, bugErrata},
			state:          bugWontfix,
			expectedLength: 2,
			expectedHas:    false,
		},
		{
			name:           "actually a set",
			states:         []JiraBugState{bugInProgress, bugInProgress, bugInProgress},
			state:          bugInProgress,
			expectedLength: 1,
			expectedHas:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			set := NewJiraBugStateSet(tc.states)
			if len(set) != tc.expectedLength {
				t.Errorf("%s: expected set to have %d members, it has %d", tc.name, tc.expectedLength, len(set))
			}
			var not string
			if !tc.expectedHas {
				not = "not "
			}
			has := set.Has(tc.state)
			if has != tc.expectedHas {
				t.Errorf("%s: expected set to %scontain %v", tc.name, not, tc.state)
			}
		})
	}
}

func TestJiraStatesMatch(t *testing.T) {
	modified := JiraBugState{Status: "MODIFIED"}
	errata := JiraBugState{Status: "CLOSED", Resolution: "ERRATA"}
	wontfix := JiraBugState{Status: "CLOSED", Resolution: "WONTFIX"}
	testCases := []struct {
		name          string
		first, second []JiraBugState
		expected      bool
	}{
		{
			name:     "empty slices match",
			expected: true,
		},
		{
			name:  "one empty, one non-empty do not match",
			first: []JiraBugState{modified},
		},
		{
			name:     "identical slices match",
			first:    []JiraBugState{modified},
			second:   []JiraBugState{modified},
			expected: true,
		},
		{
			name:     "ordering does not matter",
			first:    []JiraBugState{modified, errata},
			second:   []JiraBugState{errata, modified},
			expected: true,
		},
		{
			name:     "different slices do not match",
			first:    []JiraBugState{modified, errata},
			second:   []JiraBugState{modified, wontfix},
			expected: false,
		},
		{
			name:     "suffix in first operand is not ignored",
			first:    []JiraBugState{modified, errata},
			second:   []JiraBugState{modified},
			expected: false,
		},
		{
			name:     "suffix in second operand is not ignored",
			first:    []JiraBugState{modified},
			second:   []JiraBugState{modified, errata},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := jiraStatesMatch(tc.first, tc.second)
			if actual != tc.expected {
				t.Errorf("%s: expected %t, got %t", tc.name, tc.expected, actual)
			}
		})
	}
}
