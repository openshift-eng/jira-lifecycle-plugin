package main

import (
	"errors"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/openshift-eng/jira-lifecycle-plugin/pkg/status"
	jc "k8s.io/test-infra/prow/jira"
)

func TestValidateConfig(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		config   string
		expected error
	}{{
		name: "valid config",
		config: `default:
  '*':
    add_external_link: true
    allowed_security_levels:
    - default
    dependent_bug_states:
    - status: VERIFIED
    - status: RELEASE PENDING
    - resolution: ERRATA
      status: CLOSED
    - resolution: CURRENTRELEASE
      status: CLOSED
    is_open: true
    state_after_close:
      status: NEW
    state_after_merge:
      status: MODIFIED
    state_after_validation:
      status: POST
    valid_states:
    - status: NEW
    - status: ASSIGNED
    - status: POST`,
		expected: nil,
	}, {
		name: "invalid config",
		config: `default:
  '*':
    add_external_link: true
    allowed_security_levels:
    - default
    dependent_bug_states:
    - status: VERIFIED
    - status: RELEASE PENDING
    - resolution: ERRATA
      status: CLOSED
    - resolution: CURRENTRELEASE
      status: CLOSED
    is_open: true
    state_after_close:
      status: NEW
    state_after_merge:
      status: MODIFIED
    state_after_validation:
      status: POST
    valid_states_INVALID_CONFIG:
    - status: NEW
    - status: ASSIGNED
    - status: ON_DEV
    - status: POST`,
		expected: errors.New(`Failed to read config: error unmarshaling JSON: while decoding JSON: json: unknown field "valid_states_INVALID_CONFIG"`),
	}}
	for _, tc := range testCases {
		err := validateConfig([]byte(tc.config))
		if err == nil && tc.expected != nil {
			t.Errorf("%s: Got no error when one was expected", tc.name)
		} else if err != nil && tc.expected == nil {
			t.Errorf("%s: Got error when no errors were expected: %v", tc.name, err)
		} else if err != nil && tc.expected != nil && err.Error() != tc.expected.Error() {
			t.Errorf("%s: Got different error from expected: %v", tc.name, cmp.Diff(err.Error(), tc.expected.Error()))
		}
	}
}

func TestValidateStatuses(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		config      Config
		expectedErr []string
	}{{
		name: "Basic config with valid states",
		config: Config{
			Default: map[string]JiraBranchOptions{
				"my-branch": {
					StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
				},
			},
			Orgs: map[string]JiraOrgOptions{
				"org1": {
					Default: map[string]JiraBranchOptions{
						"my-branch": {
							StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
						},
					},
					Repos: map[string]JiraRepoOptions{
						"my-repo": {Branches: map[string]JiraBranchOptions{
							"my-branch": {
								StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
							},
						}},
					},
				},
				"org2": {
					Default: map[string]JiraBranchOptions{
						"my-branch": {
							StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
						},
					},
				},
			},
		},
		expectedErr: nil,
	}, {
		name: "Bad state in default",
		config: Config{
			Default: map[string]JiraBranchOptions{
				"my-branch": {
					StateAfterClose: &JiraBugState{Status: "CLOSER"},
				},
			},
			Orgs: map[string]JiraOrgOptions{
				"org1": {
					Default: map[string]JiraBranchOptions{
						"my-branch": {
							StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
						},
					},
					Repos: map[string]JiraRepoOptions{
						"my-repo": {Branches: map[string]JiraBranchOptions{
							"my-branch": {
								StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
							},
						}},
					},
				},
				"org2": {
					Default: map[string]JiraBranchOptions{
						"my-branch": {
							StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
						},
					},
				},
			},
		},
		expectedErr: []string{
			"Invalid statuses in `default`: my-branch has invalid status for `state_after_close`: `CLOSER`",
		},
	}, {
		name: "Invalid state in org default",
		config: Config{
			Default: map[string]JiraBranchOptions{
				"my-branch": {
					StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
				},
			},
			Orgs: map[string]JiraOrgOptions{
				"org1": {
					Default: map[string]JiraBranchOptions{
						"my-branch": {
							StateAfterClose: &JiraBugState{Status: "CLOSER"},
						},
					},
					Repos: map[string]JiraRepoOptions{
						"my-repo": {Branches: map[string]JiraBranchOptions{
							"my-branch": {
								StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
							},
						}},
					},
				},
				"org2": {
					Default: map[string]JiraBranchOptions{
						"my-branch": {
							StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
						},
					},
				},
			},
		},
		expectedErr: []string{
			"Invalid statuses in `org1/default`: my-branch has invalid status for `state_after_close`: `CLOSER`",
		},
	}, {
		name: "Invalid state in repo branch",
		config: Config{
			Default: map[string]JiraBranchOptions{
				"my-branch": {
					StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
				},
			},
			Orgs: map[string]JiraOrgOptions{
				"org1": {
					Default: map[string]JiraBranchOptions{
						"my-branch": {
							StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
						},
					},
					Repos: map[string]JiraRepoOptions{
						"my-repo": {Branches: map[string]JiraBranchOptions{
							"my-branch": {
								StateAfterClose: &JiraBugState{Status: "CLOSER"},
							},
						}},
					},
				},
				"org2": {
					Default: map[string]JiraBranchOptions{
						"my-branch": {
							StateAfterClose: &JiraBugState{Status: jc.StatusClosed},
						},
					},
				},
			},
		},
		expectedErr: []string{
			"Invalid statuses in `org1/my-repo`: my-branch has invalid status for `state_after_close`: `CLOSER`",
		},
	}, {
		name: "Multiple errors all reported",
		config: Config{
			Default: map[string]JiraBranchOptions{
				"my-branch": {
					StateAfterClose: &JiraBugState{Status: "HELLO"},
				},
			},
			Orgs: map[string]JiraOrgOptions{
				"org1": {
					Default: map[string]JiraBranchOptions{
						"my-branch": {
							StateAfterClose: &JiraBugState{Status: "WORLD"},
						},
					},
					Repos: map[string]JiraRepoOptions{
						"my-repo": {Branches: map[string]JiraBranchOptions{
							"my-branch": {
								StateAfterClose: &JiraBugState{Status: "TEST"},
							},
						}},
					},
				},
				"org2": {
					Default: map[string]JiraBranchOptions{
						"my-branch": {
							StateAfterClose: &JiraBugState{Status: "INVALID"},
						},
					},
				},
			},
		},
		expectedErr: []string{
			"Invalid statuses in `default`: my-branch has invalid status for `state_after_close`: `HELLO`",
			"Invalid statuses in `org1/default`: my-branch has invalid status for `state_after_close`: `WORLD`",
			"Invalid statuses in `org1/my-repo`: my-branch has invalid status for `state_after_close`: `TEST`",
			"Invalid statuses in `org2/default`: my-branch has invalid status for `state_after_close`: `INVALID`",
		},
	}}
	for _, tc := range testCases {
		errs := validateStatuses(&tc.config)
		if len(errs) != len(tc.expectedErr) {
			t.Errorf("%s: Got different number of errors (%d) than expected (%d): %+v", tc.name, len(errs), len(tc.expectedErr), errs)
		} else {
			stringErrs := []string{}
			for _, err := range errs {
				stringErrs = append(stringErrs, err.Error())
			}
			sort.Strings(stringErrs)
			for index, err := range stringErrs {
				if err != tc.expectedErr[index] {
					t.Errorf("%s: Got different error at index %d than expected: %v", tc.name, index, err)
				}
			}
		}
	}
}

func TestCheckBranchStatuses(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		fieldName   string
		options     JiraBranchOptions
		expectedErr []error
	}{{
		name:        "Empty config",
		fieldName:   "my-repo",
		options:     JiraBranchOptions{},
		expectedErr: nil,
	}, {
		name:      "Correct config",
		fieldName: "my-repo",
		options: JiraBranchOptions{
			ValidStates: &[]JiraBugState{{
				Status: status.Assigned,
			}, {
				Status: status.New,
			}},
			DependentBugStates: &[]JiraBugState{{
				Status: status.Verified,
			}, {
				Status: status.ReleasePending,
			}},
			StateAfterValidation: &JiraBugState{Status: status.Post},
			StateAfterMerge:      &JiraBugState{Status: status.Modified},
			StateAfterClose:      &JiraBugState{Status: status.New},
		},
		expectedErr: nil,
	}, {
		name:      "Bad Valid State",
		fieldName: "my-repo",
		options: JiraBranchOptions{
			ValidStates: &[]JiraBugState{{
				Status: "invalid",
			}, {
				Status: status.New,
			}},
			DependentBugStates: &[]JiraBugState{{
				Status: status.Verified,
			}, {
				Status: status.ReleasePending,
			}},
			StateAfterValidation: &JiraBugState{Status: status.Post},
			StateAfterMerge:      &JiraBugState{Status: status.Modified},
			StateAfterClose:      &JiraBugState{Status: status.New},
		},
		expectedErr: []error{
			errors.New("my-repo has invalid status in `valid_states`: `invalid`"),
		},
	}, {
		name:      "Bad Dependent Bug State",
		fieldName: "my-repo",
		options: JiraBranchOptions{
			ValidStates: &[]JiraBugState{{
				Status: status.Assigned,
			}, {
				Status: status.New,
			}},
			DependentBugStates: &[]JiraBugState{{
				Status: "invalid",
			}, {
				Status: status.ReleasePending,
			}},
			StateAfterValidation: &JiraBugState{Status: status.Post},
			StateAfterMerge:      &JiraBugState{Status: status.Modified},
			StateAfterClose:      &JiraBugState{Status: status.New},
		},
		expectedErr: []error{
			errors.New("my-repo has invalid status in `dependent_bug_states`: `invalid`"),
		},
	}, {
		name:      "Bad validation state",
		fieldName: "my-repo",
		options: JiraBranchOptions{
			ValidStates: &[]JiraBugState{{
				Status: status.Assigned,
			}, {
				Status: status.New,
			}},
			DependentBugStates: &[]JiraBugState{{
				Status: status.Verified,
			}, {
				Status: status.ReleasePending,
			}},
			StateAfterValidation: &JiraBugState{Status: "invalid"},
			StateAfterMerge:      &JiraBugState{Status: status.Modified},
			StateAfterClose:      &JiraBugState{Status: status.New},
		},
		expectedErr: []error{
			errors.New("my-repo has invalid status for `state_after_validation`: `invalid`"),
		},
	}, {
		name:      "Bad merge state",
		fieldName: "my-repo",
		options: JiraBranchOptions{
			ValidStates: &[]JiraBugState{{
				Status: status.Assigned,
			}, {
				Status: status.New,
			}},
			DependentBugStates: &[]JiraBugState{{
				Status: status.Verified,
			}, {
				Status: status.ReleasePending,
			}},
			StateAfterValidation: &JiraBugState{Status: status.Post},
			StateAfterMerge:      &JiraBugState{Status: "invalid"},
			StateAfterClose:      &JiraBugState{Status: status.New},
		},
		expectedErr: []error{
			errors.New("my-repo has invalid status for `state_after_merge`: `invalid`"),
		},
	}, {
		name:      "Bad close state",
		fieldName: "my-repo",
		options: JiraBranchOptions{
			ValidStates: &[]JiraBugState{{
				Status: status.Assigned,
			}, {
				Status: status.New,
			}},
			DependentBugStates: &[]JiraBugState{{
				Status: status.Verified,
			}, {
				Status: status.ReleasePending,
			}},
			StateAfterValidation: &JiraBugState{Status: status.Post},
			StateAfterMerge:      &JiraBugState{Status: status.Modified},
			StateAfterClose:      &JiraBugState{Status: "invalid"},
		},
		expectedErr: []error{
			errors.New("my-repo has invalid status for `state_after_close`: `invalid`"),
		},
	}, {

		name:      "All errors reported",
		fieldName: "my-repo",
		options: JiraBranchOptions{
			ValidStates: &[]JiraBugState{{
				Status: "invalid1",
			}, {
				Status: "invalid2",
			}},
			DependentBugStates: &[]JiraBugState{{
				Status: "invalid3",
			}, {
				Status: "invalid4",
			}},
			StateAfterValidation: &JiraBugState{Status: "invalid5"},
			StateAfterMerge:      &JiraBugState{Status: "invalid6"},
			StateAfterClose:      &JiraBugState{Status: "invalid7"},
		},
		expectedErr: []error{
			errors.New("my-repo has invalid status for `state_after_close`: `invalid7`"),
			errors.New("my-repo has invalid status for `state_after_merge`: `invalid6`"),
			errors.New("my-repo has invalid status for `state_after_validation`: `invalid5`"),
			errors.New("my-repo has invalid status in `valid_states`: `invalid1`"),
			errors.New("my-repo has invalid status in `valid_states`: `invalid2`"),
			errors.New("my-repo has invalid status in `dependent_bug_states`: `invalid3`"),
			errors.New("my-repo has invalid status in `dependent_bug_states`: `invalid4`"),
		},
	}}
	for _, tc := range testCases {
		errs := checkBranchStatuses(tc.fieldName, tc.options)
		if len(errs) != len(tc.expectedErr) {
			t.Errorf("%s: Got different number of errors (%d) than expected (%d): %+v", tc.name, len(errs), len(tc.expectedErr), errs)
		} else {
			for index, err := range errs {
				if err.Error() != tc.expectedErr[index].Error() {
					t.Errorf("%s: Got different error at index %d than expected: %v", tc.name, index, err)
				}
			}
		}
	}
}
