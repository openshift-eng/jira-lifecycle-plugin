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
	if options.StateAfterClose != nil && !validStatusSet.Has(options.StateAfterClose.Status) {
		errors = append(errors, fmt.Errorf("%s has invalid status for `state_after_close`: `%s`", name, options.StateAfterClose.Status))
	}
	if options.StateAfterMerge != nil && !validStatusSet.Has(options.StateAfterMerge.Status) {
		errors = append(errors, fmt.Errorf("%s has invalid status for `state_after_merge`: `%s`", name, options.StateAfterMerge.Status))
	}
	if options.StateAfterValidation != nil && !validStatusSet.Has(options.StateAfterValidation.Status) {
		errors = append(errors, fmt.Errorf("%s has invalid status for `state_after_validation`: `%s`", name, options.StateAfterValidation.Status))
	}
	if options.ValidStates != nil {
		for _, state := range *options.ValidStates {
			if !validStatusSet.Has(state.Status) {
				errors = append(errors, fmt.Errorf("%s has invalid status in `valid_states`: `%s`", name, state.Status))
			}
		}
	}
	if options.DependentBugStates != nil {
		for _, state := range *options.DependentBugStates {
			if !validStatusSet.Has(state.Status) {
				errors = append(errors, fmt.Errorf("%s has invalid status in `dependent_bug_states`: `%s`", name, state.Status))
			}
		}
	}
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
	status.InProgress)
