package main

import (
	"fmt"

	"github.com/openshift-eng/jira-lifecycle-plugin/pkg/status"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/yaml"
)

func validateConfig(rawConfig []byte) error {
	var config Config
	if err := yaml.UnmarshalStrict(rawConfig, &config); err != nil {
		return fmt.Errorf("failed to read config: %v", err)
	}
	errors := []error{}
	errors = append(errors, validateStatuses(&config)...)
	return utilerrors.NewAggregate(errors)
}

func validateStatuses(c *Config) []error {
	errors := []error{}
	for branchName, options := range c.Default {
		newErrs := checkBranchStatuses(branchName, options)
		if len(newErrs) == 0 {
			continue
		}
		errors = append(errors, fmt.Errorf("invalid statuses in `default`: %v", utilerrors.NewAggregate(newErrs)))
	}
	for orgName, orgOptions := range c.Orgs {
		for orgBranchName, orgBranchOptions := range orgOptions.Default {
			newErrs := checkBranchStatuses(orgBranchName, orgBranchOptions)
			if len(newErrs) == 0 {
				continue
			}
			errors = append(errors, fmt.Errorf("invalid statuses in `%s/default`: %v", orgName, utilerrors.NewAggregate(newErrs)))
		}
		for repoName, repoOptions := range orgOptions.Repos {
			for branchName, branchOptions := range repoOptions.Branches {
				newErrs := checkBranchStatuses(branchName, branchOptions)
				if len(newErrs) == 0 {
					continue
				}
				errors = append(errors, fmt.Errorf("invalid statuses in `%s/%s`: %v", orgName, repoName, utilerrors.NewAggregate(newErrs)))
			}
		}
	}
	return errors
}

func checkBranchStatuses(name string, options JiraBranchOptions) []error {
	errors := []error{}
	validStateConfig := func(jiraState *JiraBugState, configStr string) {
		if jiraState != nil && !validStatusSet.Has(jiraState.Status) {
			errors = append(errors, fmt.Errorf("%s has invalid status for `%s`: `%s`", name, configStr, jiraState.Status))
		}
	}
	validStateConfig(options.StateAfterClose, "state_after_close")
	validStateConfig(options.StateAfterMerge, "state_after_merge")
	validStateConfig(options.StateAfterValidation, "state_after_validation")
	validStateConfig(options.TaskStateAfterValidation, "task_state_after_validation")
	validStateConfig(options.TaskStateAfterMerge, "task_state_after_merge")
	validStateConfig(options.TaskStateAfterClose, "task_state_after_close")

	validateStates := func(states *[]JiraBugState, configStr string) {
		if states != nil {
			for _, state := range *states {
				if !validStatusSet.Has(state.Status) {
					errors = append(errors, fmt.Errorf("%s has invalid status in `%s`: `%s`", name, configStr, state.Status))
				}
			}
		}
	}
	validateStates(options.ValidStates, "valid_states")
	validateStates(options.DependentBugStates, "dependent_bug_states")

	return errors
}

var validStatusSet = sets.NewString(status.Assigned,
	status.Closed,
	status.Modified,
	status.New,
	status.OnQA,
	status.Post,
	status.ReleasePending,
	status.Verified,
	status.Refinement,
	status.InProgress,
	status.ToDo,
	status.CodeReview,
	status.Review)
