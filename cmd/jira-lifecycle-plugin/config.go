package main

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"
)

// Jira holds the config for the jira plugin.
type Config struct {
	// Default settings mapped by branch in any repo in any org.
	// The `*` wildcard will apply to all branches.
	Default map[string]JiraBranchOptions `json:"default,omitempty"`
	// Options for specific orgs. The `*` wildcard will apply to all orgs.
	Orgs map[string]JiraOrgOptions `json:"orgs,omitempty"`
}

// JiraOrgOptions holds options for checking Jira bugs for an org.
type JiraOrgOptions struct {
	// Default settings mapped by branch in any repo in this org.
	// The `*` wildcard will apply to all branches.
	Default map[string]JiraBranchOptions `json:"default,omitempty"`
	// Options for specific repos. The `*` wildcard will apply to all repos.
	Repos map[string]JiraRepoOptions `json:"repos,omitempty"`
}

// JiraRepoOptions holds options for checking Jira bugs for a repo.
type JiraRepoOptions struct {
	// Options for specific branches in this repo.
	// The `*` wildcard will apply to all branches.
	Branches map[string]JiraBranchOptions `json:"branches,omitempty"`
}

// JiraBugState describes bug states in the Jira plugin config, used
// for example to specify states that bugs are supposed to be in or to which
// they should be made after some action.
type JiraBugState struct {
	Status     string `json:"status,omitempty"`
	Resolution string `json:"resolution,omitempty"`
}

// PrettyStatus returns:
//   - "status (resolution)" if both status and resolution are not empty
//   - "status" if only resolution is empty
//   - "any status with resolution RESOLUTION" if only status is empty
//   - "" if both status and resolution are empty
//
// This is useful in user-facing messages that communicate bug state information
func PrettyStatus(status, resolution string) string {
	if resolution == "" {
		return status
	}
	if status == "" {
		return fmt.Sprintf("any status with resolution %s", resolution)
	}

	return fmt.Sprintf("%s (%s)", status, resolution)
}

// String converts a Jira state into human-readable description
func (s *JiraBugState) String() string {
	return PrettyStatus(s.Status, s.Resolution)
}

// JiraBranchOptions describes how to check if a Jira bug is valid or not.
type JiraBranchOptions struct {
	// ExcludeDefaults excludes defaults from more generic Jira configurations.
	ExcludeDefaults *bool `json:"exclude_defaults,omitempty"`

	// ValidateByDefault determines whether a validation check is run for all pull
	// requests by default
	ValidateByDefault *bool `json:"validate_by_default,omitempty"`

	// IsOpen determines whether a bug needs to be open to be valid
	IsOpen *bool `json:"is_open,omitempty"`
	// SkipTargetVersionCheck exclude branch from the TargetVersion check
	SkipTargetVersionCheck *bool `json:"skip_target_version_check,omitempty"`
	// TargetVersion determines which release a bug needs to target to be valid
	TargetVersion *string `json:"target_version,omitempty"`
	// ValidStates determine states in which the bug may be to be valid
	ValidStates *[]JiraBugState `json:"valid_states,omitempty"`

	// DependentBugStates determine states in which a bug's dependents bugs may be
	// to deem the child bug valid.  If set, all blockers must have a valid state.
	DependentBugStates *[]JiraBugState `json:"dependent_bug_states,omitempty"`
	// DependentBugTargetVersions determines the set of valid target
	// versions for dependent bugs.  If set, all blockers must have a
	// valid target version.
	DependentBugTargetVersions *[]string `json:"dependent_bug_target_versions,omitempty"`

	// StateAfterValidation is the state to which the bug will be moved after being
	// deemed valid and linked to a PR. Will implicitly be considered a part of `ValidStates`
	// if others are set.
	StateAfterValidation *JiraBugState `json:"state_after_validation,omitempty"`
	// PreMergeStateAfterValidation is the state to which the bug will be moved after being
	// deemed valid and linked to a PR if the PR is marked as `qe-approved` and the bug's
	// AffectVersion and FixVersion are set to `premerge`. Will implicitly be considered a
	// part of `ValidStates` if others are set.
	PreMergeStateAfterValidation *JiraBugState `json:"premerge_state_after_validation,omitempty"`
	// AddExternalLink determines whether the pull request will be added to the Jira
	// bug using the ExternalBug tracker API after being validated
	AddExternalLink *bool `json:"add_external_link,omitempty"`
	// StateAfterMerge is the state to which the bug will be moved after all pull requests
	// in the external bug tracker have been merged.
	StateAfterMerge *JiraBugState `json:"state_after_merge,omitempty"`
	// PreMergeStateAfterMerge is the state to which the bug will be moved after all pull requests
	// in the external bug tracker have been merged if the PR has the `qe-approved` label and both
	// the FixVersion and AffectsVersion fields of the bug are set to `premerge`.
	PreMergeStateAfterMerge *JiraBugState `json:"premerge_state_after_merge,omitempty"`
	// StateAfterClose is the state to which the bug will be moved if all pull requests
	// in the external bug tracker have been closed.
	StateAfterClose *JiraBugState `json:"state_after_close,omitempty"`
	// PreMergeStateAfterClose is the state to which the bug will be moved if all pull requests
	// in the external bug tracker have been close if the PR has the `qe-approved` label and both
	// the FixVersion and AffectsVersion fields of the bug are set to `premerge`.
	PreMergeStateAfterClose *JiraBugState `json:"premerge_state_after_close,omitempty"`

	// AllowedSecurityLevels is a list of the name of jira issue security levels that the jira plugin can
	// link to in PRs. If an issue has a security level that is not in this list, the jira
	// plugin will not link the issue to the PR.
	AllowedSecurityLevels []string `json:"allowed_security_levels,omitempty"`

	// RequireReleaseNotes indicates whether a jira bug requires the release notes to be filled in and not
	// equal to ReleaseNotesDefaultText for the bug to be considered valid.
	RequireReleaseNotes *bool `json:"require_release_notes,omitempty"`
	// ReleaseNotesDefaultText is the default text set by Jira for new bugs.
	ReleaseNotesDefaultText *string `json:"release_notes_default_text,omitempty"`

	// IgnoreCloneLabels is a list of labels that should be excluded when cloning a bug for cherrypicks
	IgnoreCloneLabels []string `json:"ignore_clone_labels,omitempty"`
}

type JiraBugStateSet map[JiraBugState]interface{}

func NewJiraBugStateSet(states []JiraBugState) JiraBugStateSet {
	set := make(JiraBugStateSet, len(states))
	for _, state := range states {
		set[state] = nil
	}

	return set
}

func (s JiraBugStateSet) Has(state JiraBugState) bool {
	_, ok := s[state]
	return ok
}

func (s JiraBugStateSet) Insert(states ...JiraBugState) JiraBugStateSet {
	for _, state := range states {
		s[state] = nil
	}
	return s
}

func jiraStatesMatch(first, second []JiraBugState) bool {
	if len(first) != len(second) {
		return false
	}

	firstSet := NewJiraBugStateSet(first)
	secondSet := NewJiraBugStateSet(second)

	for state := range firstSet {
		if !secondSet.Has(state) {
			return false
		}
	}

	return true
}

func (o JiraBranchOptions) matches(other JiraBranchOptions) bool {
	validateByDefaultMatch := o.ValidateByDefault == nil && other.ValidateByDefault == nil ||
		(o.ValidateByDefault != nil && other.ValidateByDefault != nil && *o.ValidateByDefault == *other.ValidateByDefault)
	isOpenMatch := o.IsOpen == nil && other.IsOpen == nil ||
		(o.IsOpen != nil && other.IsOpen != nil && *o.IsOpen == *other.IsOpen)
	targetReleaseMatch := o.TargetVersion == nil && other.TargetVersion == nil ||
		(o.TargetVersion != nil && other.TargetVersion != nil && *o.TargetVersion == *other.TargetVersion)
	skipTargetVersionCheckMatch := o.SkipTargetVersionCheck == nil && other.SkipTargetVersionCheck == nil ||
		(o.SkipTargetVersionCheck != nil && other.SkipTargetVersionCheck != nil && *o.SkipTargetVersionCheck == *other.SkipTargetVersionCheck)
	bugStatesMatch := o.ValidStates == nil && other.ValidStates == nil ||
		(o.ValidStates != nil && other.ValidStates != nil && jiraStatesMatch(*o.ValidStates, *other.ValidStates))
	dependentBugStatesMatch := o.DependentBugStates == nil && other.DependentBugStates == nil ||
		(o.DependentBugStates != nil && other.DependentBugStates != nil && jiraStatesMatch(*o.DependentBugStates, *other.DependentBugStates))
	statesAfterValidationMatch := o.StateAfterValidation == nil && other.StateAfterValidation == nil ||
		(o.StateAfterValidation != nil && other.StateAfterValidation != nil && *o.StateAfterValidation == *other.StateAfterValidation)
	addExternalLinkMatch := o.AddExternalLink == nil && other.AddExternalLink == nil ||
		(o.AddExternalLink != nil && other.AddExternalLink != nil && *o.AddExternalLink == *other.AddExternalLink)
	statesAfterMergeMatch := o.StateAfterMerge == nil && other.StateAfterMerge == nil ||
		(o.StateAfterMerge != nil && other.StateAfterMerge != nil && *o.StateAfterMerge == *other.StateAfterMerge)
	preMergestatesAfterMergeMatch := o.PreMergeStateAfterMerge == nil && other.PreMergeStateAfterMerge == nil ||
		(o.PreMergeStateAfterMerge != nil && other.PreMergeStateAfterMerge != nil && *o.PreMergeStateAfterMerge == *other.PreMergeStateAfterMerge)
	releaseNotesMatch := o.RequireReleaseNotes == nil && other.RequireReleaseNotes == nil ||
		(o.RequireReleaseNotes != nil && other.RequireReleaseNotes != nil && *o.RequireReleaseNotes == *other.RequireReleaseNotes)
	releaseNotesTextMatch := o.ReleaseNotesDefaultText == nil && other.ReleaseNotesDefaultText == nil ||
		(o.ReleaseNotesDefaultText != nil && other.ReleaseNotesDefaultText != nil && *o.ReleaseNotesDefaultText == *other.ReleaseNotesDefaultText)
	ignoreCloneLabelsMatch := len(o.IgnoreCloneLabels) == 0 && len(other.IgnoreCloneLabels) == 0 ||
		(sets.New[string](o.IgnoreCloneLabels...).Equal(sets.New[string](other.IgnoreCloneLabels...)))
	return validateByDefaultMatch && isOpenMatch && targetReleaseMatch && skipTargetVersionCheckMatch && bugStatesMatch && dependentBugStatesMatch &&
		statesAfterValidationMatch && addExternalLinkMatch && statesAfterMergeMatch && preMergestatesAfterMergeMatch &&
		releaseNotesMatch && releaseNotesTextMatch && ignoreCloneLabelsMatch
}

const JiraOptionsWildcard = `*`

// OptionsForItem resolves a set of options for an item, honoring
// the `*` wildcard and doing defaulting if it is present with the
// item itself.
func JiraOptionsForItem(item string, config map[string]JiraBranchOptions) JiraBranchOptions {
	return ResolveJiraOptions(config[JiraOptionsWildcard], config[item])
}

// ResolveJiraOptions implements defaulting for a parent/child configuration,
// preferring child fields where set. This method also reflects all "Status"
// fields into matching `State` fields.
func ResolveJiraOptions(parent, child JiraBranchOptions) JiraBranchOptions {
	output := JiraBranchOptions{}

	if child.ExcludeDefaults == nil || !*child.ExcludeDefaults {
		// populate with the parent
		if parent.ExcludeDefaults != nil {
			output.ExcludeDefaults = parent.ExcludeDefaults
		}
		if parent.ValidateByDefault != nil {
			output.ValidateByDefault = parent.ValidateByDefault
		}
		if parent.IsOpen != nil {
			output.IsOpen = parent.IsOpen
		}
		if parent.TargetVersion != nil {
			output.TargetVersion = parent.TargetVersion
		}
		if parent.SkipTargetVersionCheck != nil {
			output.SkipTargetVersionCheck = parent.SkipTargetVersionCheck
		}
		if parent.ValidStates != nil {
			output.ValidStates = parent.ValidStates
		}
		if parent.DependentBugStates != nil {
			output.DependentBugStates = parent.DependentBugStates
		}
		if parent.DependentBugTargetVersions != nil {
			output.DependentBugTargetVersions = parent.DependentBugTargetVersions
		}
		if parent.StateAfterValidation != nil {
			output.StateAfterValidation = parent.StateAfterValidation
		}
		if parent.PreMergeStateAfterValidation != nil {
			output.PreMergeStateAfterValidation = parent.PreMergeStateAfterValidation
		}
		if parent.AddExternalLink != nil {
			output.AddExternalLink = parent.AddExternalLink
		}
		if parent.StateAfterMerge != nil {
			output.StateAfterMerge = parent.StateAfterMerge
		}
		if parent.PreMergeStateAfterMerge != nil {
			output.PreMergeStateAfterMerge = parent.PreMergeStateAfterMerge
		}
		if parent.StateAfterClose != nil {
			output.StateAfterClose = parent.StateAfterClose
		}
		if parent.PreMergeStateAfterClose != nil {
			output.PreMergeStateAfterClose = parent.PreMergeStateAfterClose
		}
		if parent.AllowedSecurityLevels != nil {
			output.AllowedSecurityLevels = sets.NewString(output.AllowedSecurityLevels...).Insert(parent.AllowedSecurityLevels...).List()
		}
		if parent.IgnoreCloneLabels != nil {
			output.IgnoreCloneLabels = sets.NewString(output.IgnoreCloneLabels...).Insert(parent.IgnoreCloneLabels...).List()
		}
		if parent.RequireReleaseNotes != nil {
			output.RequireReleaseNotes = parent.RequireReleaseNotes
		}
		if parent.ReleaseNotesDefaultText != nil {
			output.ReleaseNotesDefaultText = parent.ReleaseNotesDefaultText
		}
	}

	// override with the child
	if child.ExcludeDefaults != nil {
		output.ExcludeDefaults = child.ExcludeDefaults
	}
	if child.ValidateByDefault != nil {
		output.ValidateByDefault = child.ValidateByDefault
	}
	if child.IsOpen != nil {
		output.IsOpen = child.IsOpen
	}
	if child.TargetVersion != nil {
		output.TargetVersion = child.TargetVersion
	}
	if child.SkipTargetVersionCheck != nil {
		output.SkipTargetVersionCheck = child.SkipTargetVersionCheck
	}

	if child.ValidStates != nil {
		output.ValidStates = child.ValidStates
	}

	if child.DependentBugStates != nil {
		output.DependentBugStates = child.DependentBugStates
	}
	if child.DependentBugTargetVersions != nil {
		output.DependentBugTargetVersions = child.DependentBugTargetVersions
	}
	if child.StateAfterValidation != nil {
		output.StateAfterValidation = child.StateAfterValidation
	}
	if child.PreMergeStateAfterValidation != nil {
		output.PreMergeStateAfterValidation = child.PreMergeStateAfterValidation
	}
	if child.AddExternalLink != nil {
		output.AddExternalLink = child.AddExternalLink
	}
	if child.StateAfterMerge != nil {
		output.StateAfterMerge = child.StateAfterMerge
	}
	if child.PreMergeStateAfterMerge != nil {
		output.PreMergeStateAfterMerge = child.PreMergeStateAfterMerge
	}
	if child.StateAfterClose != nil {
		output.StateAfterClose = child.StateAfterClose
	}
	if child.PreMergeStateAfterClose != nil {
		output.PreMergeStateAfterClose = child.PreMergeStateAfterClose
	}
	if child.AllowedSecurityLevels != nil {
		output.AllowedSecurityLevels = sets.NewString(output.AllowedSecurityLevels...).Insert(child.AllowedSecurityLevels...).List()
	}
	if child.IgnoreCloneLabels != nil {
		output.IgnoreCloneLabels = sets.NewString(output.IgnoreCloneLabels...).Insert(child.IgnoreCloneLabels...).List()
	}
	if child.RequireReleaseNotes != nil {
		output.RequireReleaseNotes = child.RequireReleaseNotes
	}
	if child.ReleaseNotesDefaultText != nil {
		output.ReleaseNotesDefaultText = child.ReleaseNotesDefaultText
	}

	return output
}

// OptionsForBranch determines the criteria for a valid Jira bug on a branch of a repo
// by defaulting in a cascading way, in the following order (later entries override earlier
// ones), always searching for the wildcard as well as the branch name: global, then org,
// repo, and finally branch-specific configuration.
func (b *Config) OptionsForBranch(org, repo, branch string) JiraBranchOptions {
	options := JiraOptionsForItem(branch, b.Default)
	orgOptions, exists := b.Orgs[org]
	if !exists {
		return options
	}
	options = ResolveJiraOptions(options, JiraOptionsForItem(branch, orgOptions.Default))

	repoOptions, exists := orgOptions.Repos[repo]
	if !exists {
		return options
	}
	options = ResolveJiraOptions(options, JiraOptionsForItem(branch, repoOptions.Branches))

	return options
}

// OptionsForRepo determines the criteria for a valid Jira bug on branches of a repo
// by defaulting in a cascading way, in the following order (later entries override earlier
// ones), always searching for the wildcard as well as the branch name: global, then org,
// repo, and finally branch-specific configuration.
func (b *Config) OptionsForRepo(org, repo string) map[string]JiraBranchOptions {
	options := map[string]JiraBranchOptions{}
	for branch := range b.Default {
		options[branch] = b.OptionsForBranch(org, repo, branch)
	}

	orgOptions, exists := b.Orgs[org]
	if exists {
		for branch := range orgOptions.Default {
			options[branch] = b.OptionsForBranch(org, repo, branch)
		}
	}

	repoOptions, exists := orgOptions.Repos[repo]
	if exists {
		for branch := range repoOptions.Branches {
			options[branch] = b.OptionsForBranch(org, repo, branch)
		}
	}

	// if there are nested defaults there is no reason to call out branches
	// from higher levels of config
	var toDelete []string
	for branch, branchOptions := range options {
		if branchOptions.matches(options[JiraOptionsWildcard]) && branch != JiraOptionsWildcard {
			toDelete = append(toDelete, branch)
		}
	}
	for _, branch := range toDelete {
		delete(options, branch)
	}

	return options
}
