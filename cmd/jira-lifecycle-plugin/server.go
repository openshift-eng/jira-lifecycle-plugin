package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/andygrunwald/go-jira"
	githubql "github.com/shurcooL/githubv4"
	"github.com/sirupsen/logrus"
	"github.com/trivago/tgo/tcontainer"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/test-infra/prow/config"
	prowconfig "k8s.io/test-infra/prow/config"
	"k8s.io/test-infra/prow/github"
	jiraclient "k8s.io/test-infra/prow/jira"
	"k8s.io/test-infra/prow/pluginhelp"
	"k8s.io/test-infra/prow/plugins"

	"github.com/openshift-eng/jira-lifecycle-plugin/pkg/helpers"
	"github.com/openshift-eng/jira-lifecycle-plugin/pkg/labels"
	"github.com/openshift-eng/jira-lifecycle-plugin/pkg/status"
)

const (
	PluginName            = "jira-lifecycle"
	issueLink             = `[Jira Issue %s](%s/browse/%s)`
	criticalSeverity      = "Critical"
	importantSeverity     = "Important"
	moderateSeverity      = "Moderate"
	lowSeverity           = "Low"
	informationalSeverity = "Informational"
)

var (
	titleMatchJiraIssue    = regexp.MustCompile(`(?i)([[:alpha:]]+-\d+,)*(NO-JIRA|NO-ISSUE|[[:alpha:]]+-\d+)+:`)
	refreshCommandMatch    = regexp.MustCompile(`(?mi)^/jira refresh\s*$`)
	qaReviewCommandMatch   = regexp.MustCompile(`(?mi)^/jira cc-qa\s*$`)
	cherrypickCommandMatch = regexp.MustCompile(`(?mi)^/jira cherrypick (OCPBUGS-(\d+),)*(OCPBUGS-(\d+))+\s*$`)
	cherrypickPRMatch      = regexp.MustCompile(`This is an automated cherry-pick of #([0-9]+)`)
)

type referencedBug struct {
	Key   string
	IsBug bool
}

type dependent struct {
	key              string
	targetVersion    *string
	multipleVersions bool
	bugState         JiraBugState
}

type server struct {
	config func() *Config

	prowConfigAgent *prowconfig.Agent
	ghc             githubClient
	jc              jiraclient.Client
}

func (s *server) helpProvider(enabledRepos []config.OrgRepo) (*pluginhelp.PluginHelp, error) {
	configInfo := make(map[string]string)
	for _, repo := range enabledRepos {
		opts := s.config().OptionsForRepo(repo.Org, repo.Repo)
		if len(opts) == 0 {
			continue
		}
		// we need to make sure the order of this help is consistent for page reloads and testing
		var branches []string
		for branch := range opts {
			branches = append(branches, branch)
		}
		sort.Strings(branches)
		var configInfoStrings []string
		configInfoStrings = append(configInfoStrings, "The plugin has the following configuration:<ul>")
		for _, branch := range branches {
			var message string
			if branch == JiraOptionsWildcard {
				message = "by default, "
			} else {
				message = fmt.Sprintf("on the %q branch, ", branch)
			}
			message += "valid bugs must "
			var conditions []string
			if opts[branch].IsOpen != nil {
				if *opts[branch].IsOpen {
					conditions = append(conditions, "be open")
				} else {
					conditions = append(conditions, "be closed")
				}
			}
			if opts[branch].TargetVersion != nil {
				if opts[branch].SkipTargetVersionCheck == nil || (opts[branch].SkipTargetVersionCheck != nil && !*opts[branch].SkipTargetVersionCheck) {
					conditions = append(conditions, fmt.Sprintf("target the %q version", *opts[branch].TargetVersion))
				}
			}
			if opts[branch].ValidStates != nil && len(*opts[branch].ValidStates) > 0 {
				pretty := strings.Join(prettyStates(*opts[branch].ValidStates), ", ")
				conditions = append(conditions, fmt.Sprintf("be in one of the following states: %s", pretty))
			}
			if opts[branch].DependentBugStates != nil || opts[branch].DependentBugTargetVersions != nil {
				conditions = append(conditions, "depend on at least one other bug")
			}
			if opts[branch].DependentBugStates != nil {
				pretty := strings.Join(prettyStates(*opts[branch].DependentBugStates), ", ")
				conditions = append(conditions, fmt.Sprintf("have all dependent bugs in one of the following states: %s", pretty))
			}
			if opts[branch].DependentBugTargetVersions != nil {
				conditions = append(conditions, fmt.Sprintf("have all dependent bugs in one of the following target versions: %s", strings.Join(*opts[branch].DependentBugTargetVersions, ", ")))
			}
			switch len(conditions) {
			case 0:
				message += "exist"
			case 1:
				message += conditions[0]
			case 2:
				message += fmt.Sprintf("%s and %s", conditions[0], conditions[1])
			default:
				conditions[len(conditions)-1] = fmt.Sprintf("and %s", conditions[len(conditions)-1])
				message += strings.Join(conditions, ", ")
			}
			var updates []string
			if opts[branch].StateAfterValidation != nil {
				updates = append(updates, fmt.Sprintf("moved to the %s state", opts[branch].StateAfterValidation))
			}
			if opts[branch].AddExternalLink != nil && *opts[branch].AddExternalLink {
				updates = append(updates, "updated to refer to the pull request using the external bug tracker")
			}
			if opts[branch].StateAfterMerge != nil {
				updates = append(updates, fmt.Sprintf("moved to the %s state when all linked pull requests are merged", opts[branch].StateAfterMerge))
			}

			if len(updates) > 0 {
				message += ". After being linked to a pull request, bugs will be "
			}
			switch len(updates) {
			case 0:
			case 1:
				message += updates[0]
			case 2:
				message += fmt.Sprintf("%s and %s", updates[0], updates[1])
			default:
				updates[len(updates)-1] = fmt.Sprintf("and %s", updates[len(updates)-1])
				message += strings.Join(updates, ", ")
			}
			configInfoStrings = append(configInfoStrings, "<li>"+message+".</li>")
		}
		configInfoStrings = append(configInfoStrings, "</ul>")

		configInfo[repo.String()] = strings.Join(configInfoStrings, "\n")
	}
	str := func(s string) *string { return &s }
	yes := true
	no := false
	yamlSnippet, err := plugins.CommentMap.GenYaml(&Config{
		Default: map[string]JiraBranchOptions{
			"*": {
				ValidateByDefault: &yes,
				IsOpen:            &yes,
				TargetVersion:     str("version1"),
				ValidStates: &[]JiraBugState{
					{
						Status: "MODIFIED",
					},
					{
						Status:     "CLOSED",
						Resolution: "ERRATA",
					},
				},
				DependentBugStates: &[]JiraBugState{
					{
						Status: "MODIFIED",
					},
				},
				DependentBugTargetVersions: &[]string{"version1", "version2"},
				StateAfterValidation: &JiraBugState{
					Status: "VERIFIED",
				},
				AddExternalLink: &no,
				StateAfterMerge: &JiraBugState{
					Status:     "RELEASE_PENDING",
					Resolution: "RESOLVED",
				},
				StateAfterClose: &JiraBugState{
					Status:     "RESET",
					Resolution: "FIXED",
				},
				AllowedSecurityLevels: []string{"group1", "groups2"},
			},
		},
		Orgs: map[string]JiraOrgOptions{
			"org": {
				Default: map[string]JiraBranchOptions{
					"*": {
						ExcludeDefaults:   &yes,
						ValidateByDefault: &yes,
						IsOpen:            &yes,
						TargetVersion:     str("version1"),
						ValidStates: &[]JiraBugState{
							{
								Status: "MODIFIED",
							},
							{
								Status:     "CLOSED",
								Resolution: "ERRATA",
							},
						},
						DependentBugStates: &[]JiraBugState{
							{
								Status: "MODIFIED",
							},
						},
						DependentBugTargetVersions: &[]string{"version1", "version2"},
						StateAfterValidation: &JiraBugState{
							Status: "VERIFIED",
						},
						AddExternalLink: &no,
						StateAfterMerge: &JiraBugState{
							Status:     "RELEASE_PENDING",
							Resolution: "RESOLVED",
						},
						StateAfterClose: &JiraBugState{
							Status:     "RESET",
							Resolution: "FIXED",
						},
						AllowedSecurityLevels: []string{"group1", "groups2"},
					},
				},
				Repos: map[string]JiraRepoOptions{
					"repo": {
						Branches: map[string]JiraBranchOptions{
							"branch": {
								ExcludeDefaults:   &no,
								ValidateByDefault: &yes,
								IsOpen:            &yes,
								TargetVersion:     str("version1"),
								ValidStates: &[]JiraBugState{
									{
										Status: "MODIFIED",
									},
									{
										Status:     "CLOSED",
										Resolution: "ERRATA",
									},
								},
								DependentBugStates: &[]JiraBugState{
									{
										Status: "MODIFIED",
									},
								},
								DependentBugTargetVersions: &[]string{"version1", "version2"},
								StateAfterValidation: &JiraBugState{
									Status: "VERIFIED",
								},
								AddExternalLink: &no,
								StateAfterMerge: &JiraBugState{
									Status:     "RELEASE_PENDING",
									Resolution: "RESOLVED",
								},
								StateAfterClose: &JiraBugState{
									Status:     "RESET",
									Resolution: "FIXED",
								},
								AllowedSecurityLevels: []string{"group1", "groups2"},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		logrus.WithError(err).Warnf("cannot generate comments for %s plugin", PluginName)
	}
	pluginHelp := &pluginhelp.PluginHelp{
		Description: "The jira plugin ensures that pull requests reference a valid Jira bug in their title.",
		Config:      configInfo,
		Snippet:     yamlSnippet,
	}
	pluginHelp.AddCommand(pluginhelp.Command{
		Usage:       "/jira refresh",
		Description: "Check Jira for a valid bug referenced in the PR title",
		Featured:    false,
		WhoCanUse:   "Anyone",
		Examples:    []string{"/jira refresh"},
	})
	pluginHelp.AddCommand(pluginhelp.Command{
		Usage:       "/jira cc-qa",
		Description: "Request PR review from QA contact specified in Jira",
		Featured:    false,
		WhoCanUse:   "Anyone",
		Examples:    []string{"/jira cc-qa"},
	})
	pluginHelp.AddCommand(pluginhelp.Command{
		Usage:       "/jira cherrypick jiraBugKey",
		Description: "Cherrypick a jira bug and link it to the current PR",
		Featured:    false,
		WhoCanUse:   "Anyone",
		Examples:    []string{"/jira cherrypick OCPBUGS-1234"},
	})
	return pluginHelp, nil
}

type githubClient interface {
	EditComment(org, repo string, id int, comment string) error
	GetIssue(org, repo string, number int) (*github.Issue, error)
	EditIssue(org, repo string, number int, issue *github.Issue) (*github.Issue, error)
	ListIssueComments(org, repo string, number int) ([]github.IssueComment, error)
	GetPullRequest(org, repo string, number int) (*github.PullRequest, error)
	CreateComment(owner, repo string, number int, comment string) error
	GetIssueLabels(org, repo string, number int) ([]github.Label, error)
	AddLabel(owner, repo string, number int, label string) error
	RemoveLabel(owner, repo string, number int, label string) error
	WasLabelAddedByHuman(org, repo string, num int, label string) (bool, error)
	QueryWithGitHubAppsSupport(ctx context.Context, q interface{}, vars map[string]interface{}, org string) error
	BotUserChecker() (func(candidate string) bool, error)
}

func (s *server) handleIssueComment(l *logrus.Entry, e github.IssueCommentEvent) {
	cfg := s.config()
	event, err := digestComment(s.ghc, l, e)
	if err != nil {
		l.Errorf("failed to digest comment: %v", err)
	}
	if event != nil {
		options := cfg.OptionsForBranch(event.org, event.repo, event.baseRef)
		if err := handle(s.jc, s.ghc, options, l, *event, s.prowConfigAgent.Config().AllRepos); err != nil {
			l.Errorf("failed to handle comment: %v", err)
		}
	}
}

func handle(jc jiraclient.Client, ghc githubClient, options JiraBranchOptions, log *logrus.Entry, e event, allRepos sets.String) error {
	comment := e.comment(ghc)
	if !e.missing {
		for _, refBug := range e.bugs {
			if refBug.IsBug && refBug.Key != "" {
				issue, err := getJira(jc, refBug.Key, log, comment)
				if err != nil || issue == nil {
					return err
				}
				bugAllowed, err := isBugAllowed(issue, options.AllowedSecurityLevels)
				if err != nil {
					return err
				}
				if !bugAllowed {
					// ignore bugs that are in non-allowed security levels for this repo
					if e.opened || e.refresh {
						response := fmt.Sprintf(issueLink+" is in a security level that is not in the allowed security levels for this repo.", refBug.Key, jc.JiraURL(), refBug.Key)
						if len(options.AllowedSecurityLevels) > 0 {
							response += "\nAllowed security levels for this repo are:"
							for _, group := range options.AllowedSecurityLevels {
								response += "\n- " + group
							}
						} else {
							response += " There are no allowed security levels configured for this repo."
						}
						return comment(response)
					}
					return nil
				}
			}
		}
	}
	// cherrypicks follow a different pattern than normal validation
	if e.cherrypick {
		return handleCherrypick(e, ghc, jc, options, log)
	}
	// merges follow a different pattern from the normal validation
	if e.merged {
		return handleMerge(e, ghc, jc, options, log, allRepos)
	}
	// close events follow a different pattern from the normal validation
	if e.closed && !e.merged {
		return handleClose(e, ghc, jc, options, log)
	}

	var needsJiraValidRefLabel, needsJiraValidBugLabel, needsJiraInvalidBugLabel bool
	var response, severityLabel string
	var invalidIssues []string
	if !e.noJira {
		for _, refBug := range e.bugs {
			// separate responses for different bugs
			if response != "" {
				response += "\n\n"
			}
			var issue *jira.Issue
			var err error
			if !e.missing {
				issue, err = getJira(jc, refBug.Key, log, comment)
				if err != nil {
					return err
				}
			}

			if issue == nil {
				invalidIssues = append(invalidIssues, refBug.Key)
			} else {
				needsJiraValidRefLabel = true
				premergeUpdated := false
				// check labels for premerge verification
				if refBug.IsBug {
					if labels, err := ghc.GetIssueLabels(e.org, e.repo, e.number); err != nil {
						log.WithError(err).Warn("Could not list labels on PR")
					} else {
						premergeVerified := isPreMergeVerified(issue, labels)
						if premergeVerified && options.PreMergeStateAfterValidation != nil {
							if options.PreMergeStateAfterValidation.Status != "" && (issue.Fields.Status == nil || !strings.EqualFold(issue.Fields.Status.Name, options.PreMergeStateAfterValidation.Status)) {
								if err := jc.UpdateStatus(issue.Key, options.PreMergeStateAfterValidation.Status); err != nil {
									log.WithError(err).Warn("Unexpected error updating jira issue.")
									response += formatError(fmt.Sprintf("updating to the %s state", options.PreMergeStateAfterValidation.Status), jc.JiraURL(), refBug.Key, err)
									continue
								}
								premergeUpdated = true
							}
							if options.PreMergeStateAfterValidation.Resolution != "" && (issue.Fields.Resolution == nil || !strings.EqualFold(issue.Fields.Status.Name, options.PreMergeStateAfterValidation.Resolution)) {
								updateIssue := jira.Issue{Key: issue.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.PreMergeStateAfterValidation.Resolution}}}
								if _, err := jc.UpdateIssue(&updateIssue); err != nil {
									log.WithError(err).Warn("Unexpected error updating jira issue.")
									response += formatError(fmt.Sprintf("updating to the %s resolution", options.PreMergeStateAfterMerge.Resolution), jc.JiraURL(), refBug.Key, err)
									continue
								}
								premergeUpdated = true
							}
						}
						// if this is a premerge verified issue, we don't want to run the usual verification on it; just treat it as a reference instead
						refBug.IsBug = !premergeVerified
					}
				}
				if !refBug.IsBug {
					// don't linkify the jira ref in this case because the prow-jira plugin will do so and we don't want it to
					// end up double-linkified.  The prow-jira plugin is configured to not linkify OCPBUGS refs, but it will
					// linkify refs to other projects.
					response += fmt.Sprintf("This pull request references %s which is a valid jira issue.", refBug.Key)
					if premergeUpdated {
						response += fmt.Sprintf(" The bug has been moved to the %s state.", PrettyStatus(options.PreMergeStateAfterValidation.Status, options.PreMergeStateAfterValidation.Resolution))
					}
					// We still want to notify if the pull request branch and bug target version mismatch
					if checkTargetVersion(options) {
						if err := validateTargetVersion(issue, *options.TargetVersion); err != nil {
							response += fmt.Sprintf("\n\nWarning: The referenced jira issue has an invalid target version for the target branch this PR targets: %v.", err)
						}
					}
				}
			}
			if refBug.IsBug && issue != nil {
				log = log.WithField("refKey", refBug.Key)

				severity, err := getSimplifiedSeverity(issue)
				if err != nil {
					return err
				}

				newSeverityLabel := getSeverityLabel(severity)
				if newSeverityLabel == labels.SeverityCritical {
					severityLabel = newSeverityLabel
				} else if newSeverityLabel == labels.SeverityImportant && severityLabel != labels.SeverityCritical {
					severityLabel = newSeverityLabel
				} else if newSeverityLabel == labels.SeverityModerate && severityLabel != labels.SeverityCritical && severityLabel != labels.SeverityImportant {
					severityLabel = newSeverityLabel
				} else if newSeverityLabel == labels.SeverityLow && severityLabel != labels.SeverityCritical && severityLabel != labels.SeverityImportant && severityLabel != labels.SeverityModerate {
					severityLabel = newSeverityLabel
				} else if newSeverityLabel == informationalSeverity && severityLabel == "" {
					severityLabel = newSeverityLabel
				}

				var dependents []dependent
				if options.DependentBugStates != nil || options.DependentBugTargetVersions != nil {
					for _, link := range issue.Fields.IssueLinks {
						// identify if bug depends on this link; multiple different types of links may be blocker types; more can be added as they are identified
						dependsOn := false
						dependsOn = dependsOn || (link.InwardIssue != nil && link.Type.Name == "Blocks" && link.Type.Inward == "is blocked by")
						dependsOn = dependsOn || (link.OutwardIssue != nil && link.Type.Name == "Depend" && link.Type.Outward == "depends on")
						if !dependsOn {
							continue
						}
						// link may be either an outward or inward issue; depends on the link type
						linkIssue := link.InwardIssue
						if linkIssue == nil {
							linkIssue = link.OutwardIssue
						}
						// the issue in the link is very trimmed down; get full link for dependentIssue list
						dependentIssue, err := jc.GetIssue(linkIssue.Key)
						if err != nil {
							return comment(formatError(fmt.Sprintf("searching for dependent bug %s", linkIssue.Key), jc.JiraURL(), refBug.Key, err))
						}
						targetVersion, err := helpers.GetIssueTargetVersion(dependentIssue)
						if err != nil {
							return comment(formatError(fmt.Sprintf("failed to get target version for %s", dependentIssue.Key), jc.JiraURL(), refBug.Key, err))
						}
						var targetVersionString *string
						if len(targetVersion) != 0 {
							targetVersionString = &targetVersion[0].Name
						}
						dependentState := JiraBugState{}
						if dependentIssue.Fields.Status != nil {
							dependentState.Status = dependentIssue.Fields.Status.Name
						}
						if dependentIssue.Fields.Resolution != nil {
							dependentState.Resolution = dependentIssue.Fields.Resolution.Name
						}
						newDependent := dependent{
							key:           dependentIssue.Key,
							targetVersion: targetVersionString,
							bugState:      dependentState,
						}
						dependents = append(dependents, newDependent)
					}
				}

				valid, validationsRun, why := validateBug(issue, dependents, options, jc.JiraURL())
				if !needsJiraInvalidBugLabel {
					needsJiraValidBugLabel, needsJiraInvalidBugLabel = valid, !valid
				}
				if valid {
					log.Debug("Valid bug found.")
					response += fmt.Sprintf(`This pull request references `+issueLink+`, which is valid.`, refBug.Key, jc.JiraURL(), refBug.Key)
					// if configured, move the bug to the new state
					if options.StateAfterValidation != nil {
						if options.StateAfterValidation.Status != "" && (issue.Fields.Status == nil || !strings.EqualFold(options.StateAfterValidation.Status, issue.Fields.Status.Name)) {
							if err := jc.UpdateStatus(issue.ID, options.StateAfterValidation.Status); err != nil {
								log.WithError(err).Warn("Unexpected error updating jira issue.")
								return comment(formatError(fmt.Sprintf("updating to the %s state", options.StateAfterValidation.Status), jc.JiraURL(), refBug.Key, err))
							}
							if options.StateAfterValidation.Resolution != "" && (issue.Fields.Resolution == nil || !strings.EqualFold(options.StateAfterValidation.Resolution, issue.Fields.Resolution.Name)) {
								updateIssue := jira.Issue{Key: issue.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.StateAfterValidation.Resolution}}}
								if _, err := jc.UpdateIssue(&updateIssue); err != nil {
									log.WithError(err).Warn("Unexpected error updating jira issue.")
									return comment(formatError(fmt.Sprintf("updating to the %s resolution", options.StateAfterValidation.Resolution), jc.JiraURL(), refBug.Key, err))
								}
							}
							response += fmt.Sprintf(" The bug has been moved to the %s state.", options.StateAfterValidation)
						}
					}

					response += "\n\n<details>"
					if len(validationsRun) == 0 {
						response += "<summary>No validations were run on this bug</summary>"
					} else {
						response += fmt.Sprintf("<summary>%d validation(s) were run on this bug</summary>\n", len(validationsRun))
					}
					for _, validation := range validationsRun {
						response += fmt.Sprint("\n* ", validation)
					}
					response += "</details>"

					qaContactDetail, err := helpers.GetIssueQaContact(issue)
					if err != nil {
						return comment(formatError("processing qa contact information for the bug", jc.JiraURL(), refBug.Key, err))
					}
					if qaContactDetail == nil {
						if e.cc {
							response += fmt.Sprintf(issueLink+" does not have a QA contact, skipping assignment", refBug.Key, jc.JiraURL(), refBug.Key)
						}
					} else if qaContactDetail.EmailAddress == "" {
						if e.cc {
							response += fmt.Sprintf("QA contact for "+issueLink+" does not have a listed email, skipping assignment", refBug.Key, jc.JiraURL(), refBug.Key)
						}
					} else {
						query := &emailToLoginQuery{}
						email := qaContactDetail.EmailAddress
						queryVars := map[string]interface{}{
							"email": githubql.String(email),
						}
						err := ghc.QueryWithGitHubAppsSupport(context.Background(), query, queryVars, e.org)
						if err != nil {
							log.WithError(err).Error("Failed to run graphql github query")
							return comment(formatError(fmt.Sprintf("querying GitHub for users with public email (%s)", email), jc.JiraURL(), refBug.Key, err))
						}
						response += fmt.Sprint("\n\n", processQuery(query, email, log))
					}
				} else {
					log.Debug("Invalid bug found.")
					var formattedReasons string
					for _, reason := range why {
						formattedReasons += fmt.Sprintf(" - %s\n", reason)
					}
					response += fmt.Sprintf(`This pull request references `+issueLink+`, which is invalid:
%s
Comment <code>/jira refresh</code> to re-evaluate validity if changes to the Jira bug are made, or edit the title of this pull request to link to a different bug.`, refBug.Key, jc.JiraURL(), refBug.Key, formattedReasons)
				}

				if options.AddExternalLink != nil && *options.AddExternalLink {
					changed, err := upsertGitHubLinkToIssue(log, issue.ID, jc, e)
					if err != nil {
						log.WithError(err).Warn("Unexpected error adding external tracker bug to Jira bug.")
						return comment(formatError("adding this pull request to the external tracker bugs", jc.JiraURL(), refBug.Key, err))
					}
					if changed {
						response += "\n\nThe bug has been updated to refer to the pull request using the external bug tracker."
					}
				}
			}
		}
	} else {
		needsJiraValidRefLabel = true
		response = "This pull request explicitly references no jira issue."
	}

	// ensure label state is correct. Do not propagate errors
	// as it is more important to report to the user than to
	// fail early on a label check.
	currentLabels, err := ghc.GetIssueLabels(e.org, e.repo, e.number)
	if err != nil {
		log.WithError(err).Warn("Could not list labels on PR")
	}
	var hasJiraValidBugLabel, hasJiraValidRefLabel, hasJiraInvalidBugLabel bool
	var severityLabelToRemove string
	for _, l := range currentLabels {
		if l.Name == labels.JiraValidBug {
			hasJiraValidBugLabel = true
		}
		if l.Name == labels.JiraInvalidBug {
			hasJiraInvalidBugLabel = true
		}
		if l.Name == labels.JiraValidRef {
			hasJiraValidRefLabel = true
		}

		if l.Name == labels.SeverityCritical ||
			l.Name == labels.SeverityImportant ||
			l.Name == labels.SeverityModerate ||
			l.Name == labels.SeverityLow ||
			l.Name == labels.SeverityInformational {
			severityLabelToRemove = l.Name
		}
	}

	// on missing issue, comment only on explicit commands and on label removal.
	if e.missing && (e.refresh || e.cc || hasJiraInvalidBugLabel || hasJiraValidBugLabel || hasJiraValidRefLabel) {
		response = `No Jira issue is referenced in the title of this pull request.
To reference a jira issue, add 'XYZ-NNN:' to the title of this pull request and request another refresh with <code>/jira refresh</code>.`
	} else if !e.noJira && len(invalidIssues) != 0 && (e.refresh || e.cc || hasJiraInvalidBugLabel || hasJiraValidBugLabel) {
		// if the user attempted to reference a jira key, but we couldn't find the key in jira, give feedback to the user.
		response = fmt.Sprintf("The referenced Jira(s) %v could not be located, all automatically applied jira labels will be removed.", invalidIssues)
		needsJiraValidRefLabel = false
	}

	var labelsChanged bool
	if severityLabelToRemove != "" && severityLabel != severityLabelToRemove {
		if err := ghc.RemoveLabel(e.org, e.repo, e.number, severityLabelToRemove); err != nil {
			log.WithError(err).Error("Failed to remove severity bug label.")
		}
		labelsChanged = true
	}
	if severityLabel != "" && severityLabel != severityLabelToRemove {
		if err := ghc.AddLabel(e.org, e.repo, e.number, severityLabel); err != nil {
			log.WithError(err).Error("Failed to add severity bug label.")
		}
		labelsChanged = true
	}

	if hasJiraValidRefLabel && !needsJiraValidRefLabel {
		humanLabelled, err := ghc.WasLabelAddedByHuman(e.org, e.repo, e.number, labels.JiraValidRef)
		if err != nil {
			// Return rather than potentially doing the wrong thing. The user can re-trigger us.
			return fmt.Errorf("failed to check if %s label was added by a human: %w", labels.JiraValidRef, err)
		}
		if humanLabelled {
			needsJiraValidRefLabel = true
			response += fmt.Sprintf("\n\nRetaining the %s label as it was manually added.", labels.JiraValidRef)
		}
	}

	if hasJiraValidBugLabel && !needsJiraValidBugLabel {
		humanLabelled, err := ghc.WasLabelAddedByHuman(e.org, e.repo, e.number, labels.JiraValidBug)
		if err != nil {
			// Return rather than potentially doing the wrong thing. The user can re-trigger us.
			return fmt.Errorf("failed to check if %s label was added by a human: %w", labels.JiraValidBug, err)
		}
		if humanLabelled {
			// This will make us remove the invalid label if it exists but saves us another check if it was
			// added by a human. It is reasonable to assume that it should be absent if the valid label was
			// manually added.
			needsJiraInvalidBugLabel = false
			needsJiraValidBugLabel = true
			response += fmt.Sprintf("\n\nRetaining the %s label as it was manually added.", labels.JiraValidBug)
		}
	}

	if needsJiraValidRefLabel {
		if !hasJiraValidRefLabel {
			if err := ghc.AddLabel(e.org, e.repo, e.number, labels.JiraValidRef); err != nil {
				log.WithError(err).Error("Failed to add valid ref label.")
			}
			labelsChanged = true
		}
	} else {
		if hasJiraValidRefLabel {
			if err := ghc.RemoveLabel(e.org, e.repo, e.number, labels.JiraValidRef); err != nil {
				log.WithError(err).Error("Failed to remove valid ref label.")
			}
			labelsChanged = true
		}
	}

	if needsJiraValidBugLabel {
		if !hasJiraValidBugLabel {
			if err := ghc.AddLabel(e.org, e.repo, e.number, labels.JiraValidBug); err != nil {
				log.WithError(err).Error("Failed to add valid bug label.")
			}
			labelsChanged = true
		}
	} else {
		if hasJiraValidBugLabel {
			if err := ghc.RemoveLabel(e.org, e.repo, e.number, labels.JiraValidBug); err != nil {
				log.WithError(err).Error("Failed to remove valid bug label.")
			}
			labelsChanged = true
		}
	}

	if needsJiraInvalidBugLabel && !hasJiraInvalidBugLabel {
		if err := ghc.AddLabel(e.org, e.repo, e.number, labels.JiraInvalidBug); err != nil {
			log.WithError(err).Error("Failed to add invalid bug label.")
		}
		labelsChanged = true
	} else if !needsJiraInvalidBugLabel && hasJiraInvalidBugLabel {
		if err := ghc.RemoveLabel(e.org, e.repo, e.number, labels.JiraInvalidBug); err != nil {
			log.WithError(err).Error("Failed to remove invalid bug label.")
		}
		labelsChanged = true
	}

	var duplicateComment bool
	// we always want to comment if the labels changed or a refresh was manually triggered
	if !labelsChanged && !e.refresh {
		comments, err := ghc.ListIssueComments(e.org, e.repo, e.number)
		if err != nil {
			log.WithError(err).Error("Failed to list issue comments.")
		} else {
			// comments are returned in order of ID, which is oldest first. Reverse it
			for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
				comments[i], comments[j] = comments[j], comments[i]
			}
			isBot, err := ghc.BotUserChecker()
			if err != nil {
				log.WithError(err).Error("Failed to create bot user checker.")
			} else {
				var lastBotComment *github.IssueComment
				for _, comment := range comments {
					if isBot(comment.User.Login) {
						lastBotComment = &comment
						break
					}
				}
				if lastBotComment != nil {
					// the comment function prepends the user and appends details (which may be different for different events),
					// so we can't do an exact match. A `strings.Contains` should be good enough
					if strings.Contains(lastBotComment.Body, response) {
						duplicateComment = true
					}
				}
			}
		}
	}

	if response != "" && !duplicateComment {
		return comment(response)
	}
	return nil
}

// getSimplifiedSeverity retrieves the severity of the issue and trims the image tags that precede
// the name of the severity, which are a nuisance for automation
func getSimplifiedSeverity(issue *jira.Issue) (string, error) {
	severity, err := helpers.GetIssueSeverity(issue)
	if err != nil {
		return "", fmt.Errorf("Failed to get severity of issue %s", issue.Key)
	}
	if severity == nil {
		return "unset", nil
	}
	// the values of the severity fields in redhat jira have an image before them
	// (ex: <img alt=\"\" src=\"/images/icons/priorities/medium.svg\" width=\"16\" height=\"16\"> Medium)
	// we need to trim that off before returning. There is always a space between the image and the text,
	// so we can split on spaces and take the last element
	splitSeverity := strings.Split(severity.Value, " ")
	return splitSeverity[len(splitSeverity)-1], nil
}

func isPreMergeVerified(issue *jira.Issue, prLabels []github.Label) bool {
	var hasLabel, hasFixVersions, hasAffectsVersions bool
	for _, label := range prLabels {
		if label.Name == labels.QEApproved {
			hasLabel = true
			break
		}
	}
	if issue != nil && issue.Fields != nil {
		for _, version := range issue.Fields.FixVersions {
			if version != nil && version.Name == "premerge" {
				hasFixVersions = true
				break
			}
		}
		for _, version := range issue.Fields.AffectsVersions {
			if version != nil && version.Name == "premerge" {
				hasAffectsVersions = true
				break
			}
		}
	}
	return hasLabel && hasFixVersions && hasAffectsVersions
}

type line struct {
	content   string
	replacing bool
}

func getLines(text string) []line {
	var lines []line
	rawLines := strings.Split(text, "\n")
	var prefixCount int
	for _, rawLine := range rawLines {
		if strings.HasPrefix(rawLine, "```") {
			prefixCount++
		}
		l := line{content: rawLine, replacing: true}

		// Literal codeblocks
		if strings.HasPrefix(rawLine, "    ") {
			l.replacing = false
		}
		if prefixCount%2 == 1 {
			l.replacing = false
		}
		lines = append(lines, l)
	}
	return lines
}

func insertLinksIntoComment(body string, issueNames []string, jiraBaseURL string) string {
	var linesWithLinks []string
	lines := getLines(body)
	for _, line := range lines {
		if line.replacing {
			linesWithLinks = append(linesWithLinks, insertLinksIntoLine(line.content, issueNames, jiraBaseURL))
			continue
		}
		linesWithLinks = append(linesWithLinks, line.content)
	}
	return strings.Join(linesWithLinks, "\n")
}

func insertLinksIntoLine(line string, issueNames []string, jiraBaseURL string) string {
	for _, issue := range issueNames {
		replacement := fmt.Sprintf("[%s](%s/browse/%s)", issue, jiraBaseURL, issue)
		line = replaceStringIfNeeded(line, issue, replacement)
	}
	return line
}

// replaceStringIfNeeded replaces a string if it is not prefixed by:
// * `[` which we use as heuristic for "Already replaced",
// * `/` which we use as heuristic for "Part of a link in a previous replacement",
// * ``` (backtick) which we use as heuristic for "Inline code".
// If golang would support back-references in regex replacements, this would have been a lot
func replaceStringIfNeeded(text, old, new string) string {
	if old == "" {
		return text
	}

	var result string

	// Golangs stdlib has no strings.IndexAll, only funcs to get the first
	// or last index for a substring. Definitions/condition/assignments are not
	// in the header of the loop because that makes it completely unreadable.
	var allOldIdx []int
	var startingIdx int
	for {
		idx := strings.Index(text[startingIdx:], old)
		if idx == -1 {
			break
		}
		idx = startingIdx + idx
		// Since we always look for a non-empty string, we know that idx++
		// can not be out of bounds
		allOldIdx = append(allOldIdx, idx)
		startingIdx = idx + 1
	}

	startingIdx = 0
	for _, idx := range allOldIdx {
		result += text[startingIdx:idx]
		if idx == 0 || (text[idx-1] != '[' && text[idx-1] != '/') && text[idx-1] != '`' {
			result += new
		} else {
			result += old
		}
		startingIdx = idx + len(old)
	}
	result += text[startingIdx:]

	return result
}

func prURLFromCommentURL(url string) string {
	newURL := url
	if idx := strings.Index(url, "#"); idx != -1 {
		newURL = newURL[:idx]
	}
	return newURL
}

// upsertGitHubLinkToIssue adds a remote link to the github issue on the jira issue. It returns a bool indicating whether or not the
// remote link changed or was created, and an error.
func upsertGitHubLinkToIssue(log *logrus.Entry, issueID string, jc jiraclient.Client, e event) (bool, error) {
	links, err := jc.GetRemoteLinks(issueID)
	if err != nil {
		return false, fmt.Errorf("failed to get remote links: %w", err)
	}

	url := prURLFromCommentURL(e.htmlUrl)
	title := fmt.Sprintf("%s/%s#%d: %s", e.org, e.repo, e.number, e.title)
	var existingLink *jira.RemoteLink

	// Check if the same link exists already. We consider two links to be the same if the have the same URL.
	// Once it is found we have two possibilities: either it is really equal (just skip the upsert) or it
	// has to be updated (perform an upsert)
	for _, link := range links {
		if link.Object.URL == url {
			if title == link.Object.Title {
				return false, nil
			}
			link := link
			existingLink = &link
			break
		}
	}

	link := &jira.RemoteLink{
		Object: &jira.RemoteLinkObject{
			URL:   url,
			Title: title,
			Icon: &jira.RemoteLinkIcon{
				Url16x16: "https://github.com/favicon.ico",
				Title:    "GitHub",
			},
		},
	}

	if existingLink != nil {
		existingLink.Object = link.Object
		if err := jc.UpdateRemoteLink(issueID, existingLink); err != nil {
			return false, fmt.Errorf("failed to update remote link: %w", err)
		}
		log.Info("Updated jira link")
	} else {
		if _, err := jc.AddRemoteLink(issueID, link); err != nil {
			return false, fmt.Errorf("failed to add remote link: %w", err)
		}
		log.Info("Created jira link")
	}

	return true, nil
}

func (s *server) handlePullRequest(l *logrus.Entry, pre github.PullRequestEvent) {
	cfg := s.config()
	options := cfg.OptionsForBranch(pre.PullRequest.Base.Repo.Owner.Login, pre.PullRequest.Base.Repo.Name, pre.PullRequest.Base.Ref)
	event, err := digestPR(l, pre, options.ValidateByDefault)
	if err != nil {
		l.Errorf("failed to digest PR: %v", err)
	}
	if event != nil {
		if err := handle(s.jc, s.ghc, options, l, *event, s.prowConfigAgent.Config().AllRepos); err != nil {
			l.Errorf("failed to handle PR: %v", err)
		}
	}
}

func getCherryPickMatch(pre github.PullRequestEvent) (bool, int, error) {
	cherrypickMatch := cherrypickPRMatch.FindStringSubmatch(pre.PullRequest.Body)
	if cherrypickMatch != nil {
		cherrypickOf, err := strconv.Atoi(cherrypickMatch[1])
		if err != nil {
			// should be impossible based on the regex
			return false, 0, fmt.Errorf("Failed to parse cherrypick jira issue - is the regex correct? Err: %w", err)
		}
		return true, cherrypickOf, nil
	}
	return false, 0, nil
}

// digestPR determines if any action is necessary and creates the objects for handle() if it is
func digestPR(log *logrus.Entry, pre github.PullRequestEvent, validateByDefault *bool) (*event, error) {
	// These are the only actions indicating the PR title may have changed or that the PR merged or was closed
	if pre.Action != github.PullRequestActionOpened &&
		pre.Action != github.PullRequestActionReopened &&
		pre.Action != github.PullRequestActionEdited &&
		pre.Action != github.PullRequestActionClosed &&
		pre.Action != github.PullRequestActionLabeled &&
		pre.Action != github.PullRequestActionUnlabeled {
		return nil, nil
	}

	if (pre.Action == github.PullRequestActionLabeled || pre.Action == github.PullRequestActionUnlabeled) && pre.Label.Name != labels.QEApproved {
		return nil, nil
	}

	var (
		org     = pre.PullRequest.Base.Repo.Owner.Login
		repo    = pre.PullRequest.Base.Repo.Name
		baseRef = pre.PullRequest.Base.Ref
		number  = pre.PullRequest.Number
		title   = pre.PullRequest.Title
		body    = pre.PullRequest.Body
	)

	e := &event{org: org, repo: repo, baseRef: baseRef, number: number, merged: pre.PullRequest.Merged, closed: pre.Action == github.PullRequestActionClosed, opened: pre.Action == github.PullRequestActionOpened, state: pre.PullRequest.State, body: body, title: title, htmlUrl: pre.PullRequest.HTMLURL, login: pre.PullRequest.User.Login}
	// Make sure the PR title is referencing a bug
	var err error
	e.bugs, e.missing, e.noJira = jiraKeyFromTitle(title)

	// Check if PR is a cherrypick
	cherrypick, cherrypickFromPRNum, err := getCherryPickMatch(pre)
	if err != nil {
		log.WithError(err).Debug("Failed to identify if PR is a cherrypick")
		return nil, err
	} else if cherrypick {
		if pre.Action == github.PullRequestActionOpened {
			e.cherrypick = true
			e.cherrypickFromPRNum = cherrypickFromPRNum
			return e, nil
		}
	}

	if e.closed && !e.merged {
		// if the PR was closed, we do not need to check for any other
		// conditions like cherry-picks or title edits and can just
		// handle it
		return e, nil
	}

	// when exiting early from errors trying to find out if the PR previously referenced a bug,
	// we want to handle the event only if a bug is currently referenced or we are validating by
	// default
	var intermediate *event
	if !e.missing || (validateByDefault != nil && *validateByDefault) {
		intermediate = e
	}

	// Check if the previous version of the title referenced a bug.
	var changes struct {
		Title struct {
			From string `json:"from"`
		} `json:"title"`
	}
	if err := json.Unmarshal(pre.Changes, &changes); err != nil {
		// we're detecting this best-effort so we can handle it anyway
		return intermediate, nil
	}
	prevIds, missing, _ := jiraKeyFromTitle(changes.Title.From)
	if missing {
		// title did not previously reference a bug
		return intermediate, nil
	}

	// if the referenced bug has not changed in the update, ignore it
	if len(prevIds) == len(e.bugs) {
		var changed bool
		for index, prevBug := range prevIds {
			if e.bugs[index].Key != prevBug.Key {
				changed = true
				break
			}
		}
		if !changed {
			logrus.Debugf("Referenced Jira issue(s) (%+v) has not changed, not handling event.", e.bugs)
			return nil, nil
		}
	}
	// we know the PR previously referenced a bug, so whether
	// it currently does or does not reference a bug, we should
	// handle the event
	return e, nil
}

// digestComment determines if any action is necessary and creates the objects for handle() if it is
func digestComment(gc githubClient, log *logrus.Entry, ice github.IssueCommentEvent) (*event, error) {
	// Only consider new comments.
	if ice.Action != github.IssueCommentActionCreated {
		return nil, nil
	}
	// Make sure they are requesting a valid command
	var refresh, cc, cherrypick bool
	switch {
	case refreshCommandMatch.MatchString(ice.Comment.Body):
		refresh = true
	case qaReviewCommandMatch.MatchString(ice.Comment.Body):
		cc = true
	case cherrypickCommandMatch.MatchString(ice.Comment.Body):
		cherrypick = true
	default:
		return nil, nil
	}
	var (
		org    = ice.Repo.Owner.Login
		repo   = ice.Repo.Name
		number = ice.Issue.Number
	)

	// We don't support linking issues to OCPBUGS
	if !ice.Issue.IsPullRequest() {
		log.Debug("Jira bug command requested on an issue, ignoring")
		return nil, gc.CreateComment(org, repo, number, plugins.FormatResponseRaw(ice.Comment.Body, ice.Comment.HTMLURL, ice.Comment.User.Login, `Jira bug referencing is only supported for Pull Requests, not issues.`))
	}

	// Make sure the PR title is referencing a bug
	pr, err := gc.GetPullRequest(org, repo, number)
	if err != nil {
		return nil, err
	}

	e := &event{org: org, repo: repo, baseRef: pr.Base.Ref, number: number, merged: pr.Merged, state: pr.State, body: ice.Comment.Body, title: ice.Issue.Title, htmlUrl: ice.Comment.HTMLURL, login: ice.Comment.User.Login, refresh: refresh, cc: cc}

	e.bugs, e.missing, e.noJira = jiraKeyFromTitle(pr.Title)

	if cherrypick {
		mat := cherrypickCommandMatch.FindStringSubmatch(ice.Comment.Body)
		if len(mat) == 0 {
			// this shouldn't be possible due to earlier cherrypick check
			return nil, errors.New("failed to get cherrypick string match")
		}
		keys := strings.TrimPrefix(strings.TrimRight(mat[0], "\r\n "), "/jira cherrypick ")
		splitKeys := strings.Split(keys, ",")
		e.bugs = []referencedBug{} // reset bugs list to only include cherrypick comment specified bugs
		for _, key := range splitKeys {
			e.bugs = append(e.bugs, referencedBug{
				Key:   key,
				IsBug: strings.Contains(key, "OCPBUGS-"),
			})
		}
		e.cherrypick = true
		e.cherrypickCmd = true
	}

	return e, nil
}

type event struct {
	org, repo, baseRef              string
	number                          int
	bugs                            []referencedBug
	noJira                          bool
	missing, merged, closed, opened bool
	state                           string
	body, title, htmlUrl, login     string
	refresh, cc, cherrypickCmd      bool
	cherrypick                      bool
	cherrypickFromPRNum             int
}

func (e *event) comment(gc githubClient) func(body string) error {
	return func(body string) error {
		return gc.CreateComment(e.org, e.repo, e.number, plugins.FormatResponseRaw(e.body, e.htmlUrl, e.login, body))
	}
}

type queryUser struct {
	Login githubql.String
}

type queryNode struct {
	User queryUser `graphql:"... on User"`
}

type queryEdge struct {
	Node queryNode
}

type querySearch struct {
	Edges []queryEdge
}

/*
emailToLoginQuery is a graphql query struct that should result in this graphql query:

	{
	  search(type: USER, query: "email", first: 5) {
	    edges {
	      node {
	        ... on User {
	          login
	        }
	      }
	    }
	  }
	}
*/
type emailToLoginQuery struct {
	Search querySearch `graphql:"search(type:USER query:$email first:5)"`
}

// processQueryResult generates a response based on a populated emailToLoginQuery
func processQuery(query *emailToLoginQuery, email string, log *logrus.Entry) string {
	switch len(query.Search.Edges) {
	case 0:
		return fmt.Sprintf("No GitHub users were found matching the public email listed for the QA contact in Jira (%s), skipping review request.", email)
	case 1:
		return fmt.Sprintf("Requesting review from QA contact:\n/cc @%s", query.Search.Edges[0].Node.User.Login)
	default:
		response := fmt.Sprintf("Multiple GitHub users were found matching the public email listed for the QA contact in Jira (%s), skipping review request. List of users with matching email:", email)
		for _, edge := range query.Search.Edges {
			response += fmt.Sprintf("\n\t- %s", edge.Node.User.Login)
		}
		return response
	}
}

func getSeverityLabel(severity string) string {
	switch severity {
	case criticalSeverity:
		return labels.SeverityCritical
	case importantSeverity:
		return labels.SeverityImportant
	case moderateSeverity:
		return labels.SeverityModerate
	case lowSeverity:
		return labels.SeverityLow
	case informationalSeverity:
		return labels.SeverityInformational
	}
	//If we don't understand the severity, don't set it but don't error.
	return ""
}

func bugMatchesStates(bug *jira.Issue, states []JiraBugState) bool {
	if bug == nil {
		return false
	}

	bugState := JiraBugState{}
	if bug.Fields.Status != nil {
		bugState.Status = bug.Fields.Status.Name
	}
	if bug.Fields.Resolution != nil {
		bugState.Resolution = bug.Fields.Resolution.Name
	}
	return bugState.matches(states)
}

func (bs *JiraBugState) matches(states []JiraBugState) bool {
	for _, state := range states {
		if ((state.Status != "" && strings.EqualFold(state.Status, bs.Status)) || state.Status == "") &&
			((state.Resolution != "" && strings.EqualFold(state.Resolution, bs.Resolution)) || state.Resolution == "") {
			return true
		}
	}
	return false
}

func prettyStates(statuses []JiraBugState) []string {
	pretty := make([]string, 0, len(statuses))
	for _, status := range statuses {
		pretty = append(pretty, PrettyStatus(status.Status, status.Resolution))
	}
	return pretty
}

// validateBug determines if the bug matches the options and returns a description of why not
func validateBug(bug *jira.Issue, dependents []dependent, options JiraBranchOptions, jiraEndpoint string) (bool, []string, []string) {
	valid := true
	var errors []string
	var validations []string
	if options.IsOpen != nil && (bug.Fields == nil || bug.Fields.Status == nil || *options.IsOpen != !strings.EqualFold(bug.Fields.Status.Name, status.Closed)) {
		valid = false
		not := ""
		was := "isn't"
		if !*options.IsOpen {
			not = "not "
			was = "is"
		}
		errors = append(errors, fmt.Sprintf("expected the bug to %sbe open, but it %s", not, was))
	} else if options.IsOpen != nil {
		expected := "open"
		if !*options.IsOpen {
			expected = "not open"
		}
		was := "isn't"
		if !strings.EqualFold(bug.Fields.Status.Name, status.Closed) {
			was = "is"
		}
		validations = append(validations, fmt.Sprintf("bug %s open, matching expected state (%s)", was, expected))
	}

	if options.TargetVersion != nil {
		if err := validateTargetVersion(bug, *options.TargetVersion); err != nil {
			errors = append(errors, err.Error())
			valid = false
		} else {
			validations = append(validations, fmt.Sprintf("bug target version (%s) matches configured target version for branch (%s)", *options.TargetVersion, *options.TargetVersion))
		}
	}

	if options.ValidStates != nil {
		var allowed []JiraBugState
		allowed = append(allowed, *options.ValidStates...)
		if options.StateAfterValidation != nil {
			stateAlreadyExists := false
			for _, state := range allowed {
				if strings.EqualFold(state.Status, options.StateAfterValidation.Status) && strings.EqualFold(state.Resolution, options.StateAfterValidation.Resolution) {
					stateAlreadyExists = true
					break
				}
			}
			if !stateAlreadyExists {
				allowed = append(allowed, *options.StateAfterValidation)
			}
		}
		var status, resolution string
		if bug.Fields.Status != nil {
			status = bug.Fields.Status.Name
		}
		if bug.Fields.Resolution != nil {
			resolution = bug.Fields.Resolution.Name
		}
		if !bugMatchesStates(bug, allowed) {
			valid = false
			errors = append(errors, fmt.Sprintf("expected the bug to be in one of the following states: %s, but it is %s instead", strings.Join(prettyStates(allowed), ", "), PrettyStatus(status, resolution)))
		} else {
			validations = append(validations, fmt.Sprintf("bug is in the state %s, which is one of the valid states (%s)", PrettyStatus(status, resolution), strings.Join(prettyStates(allowed), ", ")))
		}
	}

	if options.RequireReleaseNotes != nil && *options.RequireReleaseNotes {
		releaseNotes, err := helpers.GetIssueReleaseNotesText(bug)
		if err != nil {
			errors = append(errors, err.Error())
			valid = false
		} else {
			if releaseNotes == nil || *releaseNotes == "" || (options.ReleaseNotesDefaultText != nil && *options.ReleaseNotesDefaultText == *releaseNotes) {
				valid = false
				errors = append(errors, "release notes must be set and not match default text")
			} else {
				validations = append(validations, "release notes are set")
			}
		}
	}

	if options.DependentBugStates != nil {
		for _, bug := range dependents {
			if !strings.HasPrefix(bug.key, "OCPBUGS-") {
				continue
			}
			if !bug.bugState.matches(*options.DependentBugStates) {
				valid = false
				expected := strings.Join(prettyStates(*options.DependentBugStates), ", ")
				actual := PrettyStatus(bug.bugState.Status, bug.bugState.Resolution)
				errors = append(errors, fmt.Sprintf("expected dependent "+issueLink+" to be in one of the following states: %s, but it is %s instead", bug.key, jiraEndpoint, bug.key, expected, actual))
			} else {
				validations = append(validations, fmt.Sprintf("dependent bug "+issueLink+" is in the state %s, which is one of the valid states (%s)", bug.key, jiraEndpoint, bug.key, PrettyStatus(bug.bugState.Status, bug.bugState.Resolution), strings.Join(prettyStates(*options.DependentBugStates), ", ")))
			}
		}
	}

	if options.DependentBugTargetVersions != nil {
		for _, bug := range dependents {
			if !strings.HasPrefix(bug.key, "OCPBUGS-") {
				continue
			}
			if bug.targetVersion == nil {
				valid = false
				errors = append(errors, fmt.Sprintf("expected dependent "+issueLink+" to target a version in %s, but no target version was set", bug.key, jiraEndpoint, bug.key, strings.Join(*options.DependentBugTargetVersions, ", ")))
			} else if bug.multipleVersions {
				valid = false
				errors = append(errors, fmt.Sprintf("expected dependent "+issueLink+" to target a version in %s, but it has multiple target versions", bug.key, jiraEndpoint, bug.key, strings.Join(*options.DependentBugTargetVersions, ", ")))
			} else if sets.NewString(*options.DependentBugTargetVersions...).Has(*bug.targetVersion) {
				validations = append(validations, fmt.Sprintf("dependent "+issueLink+" targets the %q version, which is one of the valid target versions: %s", bug.key, jiraEndpoint, bug.key, *bug.targetVersion, strings.Join(*options.DependentBugTargetVersions, ", ")))
			} else {
				valid = false
				errors = append(errors, fmt.Sprintf("expected dependent "+issueLink+" to target a version in %s, but it targets %q instead", bug.key, jiraEndpoint, bug.key, strings.Join(*options.DependentBugTargetVersions, ", "), *bug.targetVersion))
			}
		}
	}

	if len(dependents) == 0 {
		switch {
		case options.DependentBugStates != nil && options.DependentBugTargetVersions != nil:
			valid = false
			expected := strings.Join(prettyStates(*options.DependentBugStates), ", ")
			errors = append(errors, fmt.Sprintf("expected "+issueLink+" to depend on a bug targeting a version in %s and in one of the following states: %s, but no dependents were found", bug.Key, jiraEndpoint, bug.Key, strings.Join(*options.DependentBugTargetVersions, ", "), expected))
		case options.DependentBugStates != nil:
			valid = false
			expected := strings.Join(prettyStates(*options.DependentBugStates), ", ")
			errors = append(errors, fmt.Sprintf("expected "+issueLink+" to depend on a bug in one of the following states: %s, but no dependents were found", bug.Key, jiraEndpoint, bug.Key, expected))
		case options.DependentBugTargetVersions != nil:
			valid = false
			errors = append(errors, fmt.Sprintf("expected "+issueLink+" to depend on a bug targeting a version in %s, but no dependents were found", bug.Key, jiraEndpoint, bug.Key, strings.Join(*options.DependentBugTargetVersions, ", ")))
		default:
		}
	} else {
		validations = append(validations, "bug has dependents")
	}

	// make sure all dependents are part of OCPBUGS
	for _, dependent := range dependents {
		if !strings.HasPrefix(dependent.key, "OCPBUGS-") {
			valid = false
			errors = append(validations, fmt.Sprintf("dependent bug %s is not in the required `OCPBUGS` project", dependent.key))
		}
	}

	return valid, validations, errors
}

func validateTargetVersion(issue *jira.Issue, requiredTargetVersion string) error {
	issueType := ""
	if issue.Fields != nil {
		issueType = strings.ToLower(issue.Fields.Type.Name)
	} else {
		issueType = "bug"
	}
	targetVersion, err := helpers.GetIssueTargetVersion(issue)
	if err != nil {
		return fmt.Errorf("failed to get target version for %s: %v", issueType, err)
	}
	if len(targetVersion) == 0 {
		return fmt.Errorf("expected the %s to target the %q version, but no target version was set", issueType, requiredTargetVersion)
	}
	if len(targetVersion) > 1 {
		return fmt.Errorf("expected the %s to target only the %q version, but multiple target versions were set", issueType, requiredTargetVersion)
	}
	//prefixedRequiredTargetVersion := fmt.Sprintf("openshift-%s", requiredTargetVersion)
	//if requiredTargetVersion != targetVersion[0].Name && prefixedRequiredTargetVersion != targetVersion[0].Name {
	//	return fmt.Errorf("expected the %s to target either version %q or %q, but it targets %q instead", issueType, requiredTargetVersion, prefixedRequiredTargetVersion, targetVersion[0].Name)
	//}
	// TODO: Remove this truncated version check...
	truncatedRequiredTargetVersion := requiredTargetVersion
	pieces := strings.Split(requiredTargetVersion, ".")
	if len(pieces) >= 2 {
		truncatedRequiredTargetVersion = fmt.Sprintf("%s.%s", pieces[0], pieces[1])
	}
	truncatedPrefixedRequiredTargetVersion := fmt.Sprintf("openshift-%s", truncatedRequiredTargetVersion)
	if !strings.HasPrefix(targetVersion[0].Name, truncatedRequiredTargetVersion) && !strings.HasPrefix(targetVersion[0].Name, truncatedPrefixedRequiredTargetVersion) {
		return fmt.Errorf("expected the %s to target either version %q or %q, but it targets %q instead", issueType, fmt.Sprintf("%s.*", truncatedRequiredTargetVersion), fmt.Sprintf("%s.*", truncatedPrefixedRequiredTargetVersion), targetVersion[0].Name)
	}
	return nil
}

type prParts struct {
	Org  string
	Repo string
	Num  int
}

func handleMerge(e event, gc githubClient, jc jiraclient.Client, options JiraBranchOptions, log *logrus.Entry, allRepos sets.String) error {
	if options.StateAfterMerge == nil {
		return nil
	}
	if e.missing {
		return nil
	}
	comment := e.comment(gc)

	msg := ""
	for _, refBug := range e.bugs {
		if !refBug.IsBug {
			continue
		}
		if msg != "" {
			msg += "\n\n"
		}
		bug, err := getJira(jc, refBug.Key, log, comment)
		if err != nil || bug == nil {
			return err
		}
		if options.ValidStates != nil || options.StateAfterValidation != nil {
			// we should only migrate if we can be fairly certain that the bug
			// is not in a state that required human intervention to get to.
			// For instance, if a bug is closed after a PR merges it should not
			// be possible for /jira refresh to move it back to the post-merge
			// state.
			var allowed []JiraBugState
			if options.ValidStates != nil {
				allowed = append(allowed, *options.ValidStates...)
			}

			if options.StateAfterValidation != nil {
				allowed = append(allowed, *options.StateAfterValidation)
			}
			if !bugMatchesStates(bug, allowed) {
				msg += fmt.Sprintf(issueLink+" is in an unrecognized state (%s) and will not be moved to the %s state.", refBug.Key, jc.JiraURL(), refBug.Key, bug.Fields.Status.Name, options.StateAfterMerge)
				continue
			}
		}

		links, err := jc.GetRemoteLinks(bug.ID)
		if err != nil {
			log.WithError(err).Warn("Unexpected error listing external tracker bugs for Jira bug.")
			msg += formatError("searching for external tracker bugs", jc.JiraURL(), refBug.Key, err)
			continue
		}
		shouldMigrate := true
		var mergedPRs []prParts
		unmergedPrStates := map[prParts]string{}
		for _, link := range links {
			identifier := strings.TrimPrefix(link.Object.URL, "https://github.com/")
			parts := strings.Split(identifier, "/")
			if len(parts) >= 3 && parts[2] != "pull" {
				// this is not a github link
				continue
			}
			if len(parts) != 4 && !(len(parts) == 5 && (parts[4] == "" || parts[4] == "files")) && !(len(parts) == 6 && ((parts[4] == "files" && parts[5] == "") || parts[4] == "commits")) {
				log.WithError(err).Warn("Unexpected error splitting github URL for Jira external link.")
				msg += formatError(fmt.Sprintf("invalid pull identifier with %d parts: %q", len(parts), identifier), jc.JiraURL(), refBug.Key, err)
				continue
			}
			number, err := strconv.Atoi(parts[3])
			if err != nil {
				log.WithError(err).Warn("Unexpected error splitting github URL for Jira external link.")
				msg += formatError(fmt.Sprintf("invalid pull identifier: could not parse %s as number", parts[3]), jc.JiraURL(), refBug.Key, err)
				continue
			}
			item := prParts{
				Org:  parts[0],
				Repo: parts[1],
				Num:  number,
			}
			var merged bool
			var state string
			if e.org == item.Org && e.repo == item.Repo && e.number == item.Num {
				merged = e.merged
				state = e.state
			} else {
				// This could be literally anything, only process PRs in repos that are mentioned in our config, otherwise this will potentially
				// fail.
				if !allRepos.Has(item.Org + "/" + item.Repo) {
					logrus.WithField("pr", item.Org+"/"+item.Repo+"#"+strconv.Itoa(item.Num)).Debug("Not processing PR from third-party repo")
					continue
				}
				pr, err := gc.GetPullRequest(item.Org, item.Repo, item.Num)
				if err != nil {
					log.WithError(err).Warn("Unexpected error checking merge state of related pull request.")
					msg += formatError(fmt.Sprintf("checking the state of a related pull request at https://github.com/%s/%s/pull/%d", item.Org, item.Repo, item.Num), jc.JiraURL(), refBug.Key, err)
					continue
				}
				merged = pr.Merged
				state = pr.State
			}
			if merged {
				mergedPRs = append(mergedPRs, item)
			} else {
				unmergedPrStates[item] = state
			}
			// only update Jira bug status if all PRs have merged
			shouldMigrate = shouldMigrate && merged
			if !shouldMigrate {
				// we could give more complete feedback to the user by checking all PRs
				// but we save tokens by exiting when we find an unmerged one, so we
				// prefer to do that
				break
			}
		}

		link := func(pr prParts) string {
			return fmt.Sprintf("[%s/%s#%d](https://github.com/%s/%s/pull/%d)", pr.Org, pr.Repo, pr.Num, pr.Org, pr.Repo, pr.Num)
		}

		mergedMessage := func(statement string) string {
			var links []string
			for _, bug := range mergedPRs {
				links = append(links, fmt.Sprintf(" * %s", link(bug)))
			}
			return fmt.Sprintf(`%s pull requests linked via external trackers have merged:
%s

`, statement, strings.Join(links, "\n"))
		}

		var statements []string
		for bug, state := range unmergedPrStates {
			statements = append(statements, fmt.Sprintf(" * %s is %s", link(bug), state))
		}
		unmergedMessage := fmt.Sprintf(`The following pull requests linked via external trackers have not merged:
%s

These pull request must merge or be unlinked from the Jira bug in order for it to move to the next state. Once unlinked, request a bug refresh with <code>/jira refresh</code>.

`, strings.Join(statements, "\n"))

		outcomeMessage := func(action string) string {
			return fmt.Sprintf(issueLink+" has %sbeen moved to the %s state.", refBug.Key, jc.JiraURL(), refBug.Key, action, options.StateAfterMerge)
		}

		if shouldMigrate {
			labels, err := gc.GetIssueLabels(e.org, e.repo, e.number)
			if err != nil {
				log.WithError(err).Warn("Could not list labels on PR")
			}
			if isPreMergeVerified(bug, labels) {
				outcomeMessage = func(action string) string {
					return fmt.Sprintf(issueLink+" has %sbeen moved to the %s state.", refBug.Key, jc.JiraURL(), refBug.Key, action, options.PreMergeStateAfterMerge)
				}
				if options.PreMergeStateAfterMerge != nil {
					if options.PreMergeStateAfterMerge.Status != "" && (bug.Fields.Status == nil || !strings.EqualFold(bug.Fields.Status.Name, options.PreMergeStateAfterMerge.Status)) {
						if err := jc.UpdateStatus(bug.Key, options.PreMergeStateAfterMerge.Status); err != nil {
							log.WithError(err).Warn("Unexpected error updating jira bug.")
							msg += formatError(fmt.Sprintf("updating to the %s state", options.PreMergeStateAfterMerge.Status), jc.JiraURL(), refBug.Key, err)
							continue
						}
					}
					if options.PreMergeStateAfterMerge.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(bug.Fields.Status.Name, options.PreMergeStateAfterMerge.Resolution)) {
						updatebug := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.PreMergeStateAfterMerge.Resolution}}}
						if _, err := jc.UpdateIssue(&updatebug); err != nil {
							log.WithError(err).Warn("Unexpected error updating jira bug.")
							msg += formatError(fmt.Sprintf("updating to the %s resolution", options.PreMergeStateAfterMerge.Resolution), jc.JiraURL(), refBug.Key, err)
							continue
						}
					}
				}
			} else {
				if options.StateAfterMerge != nil {
					if options.StateAfterMerge.Status != "" && (bug.Fields.Status == nil || !strings.EqualFold(options.StateAfterMerge.Status, bug.Fields.Status.Name)) {
						if err := jc.UpdateStatus(refBug.Key, options.StateAfterMerge.Status); err != nil {
							log.WithError(err).Warn("Unexpected error updating jira issue.")
							msg += formatError(fmt.Sprintf("updating to the %s state", options.StateAfterMerge.Status), jc.JiraURL(), refBug.Key, err)
							continue
						}
						if options.StateAfterMerge.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(options.StateAfterMerge.Resolution, bug.Fields.Resolution.Name)) {
							updateIssue := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.StateAfterMerge.Resolution}}}
							if _, err := jc.UpdateIssue(&updateIssue); err != nil {
								log.WithError(err).Warn("Unexpected error updating jira issue.")
								msg += formatError(fmt.Sprintf("updating to the %s resolution", options.StateAfterMerge.Resolution), jc.JiraURL(), refBug.Key, err)
								continue
							}
						}
					}
				}
			}
			msg += fmt.Sprintf(issueLink+": %s%s", refBug.Key, jc.JiraURL(), refBug.Key, mergedMessage("All"), outcomeMessage(""))
			continue
		}
		msg += fmt.Sprintf(issueLink+": %s%s%s", refBug.Key, jc.JiraURL(), refBug.Key, mergedMessage("Some"), unmergedMessage, outcomeMessage("not "))
	}
	if msg == "" {
		return nil
	} else {
		return comment(msg)
	}
}

func identifyClones(issue *jira.Issue) []*jira.Issue {
	var clones []*jira.Issue
	for _, link := range issue.Fields.IssueLinks {
		// the inward issue of the Cloners type is always the clone of the provided; if it is unset (nil), then
		// the issue being linked is being cloned by the provided issue
		if link.Type.Name == "Cloners" && link.InwardIssue != nil {
			clones = append(clones, link.InwardIssue)
		}
	}
	return clones
}

func handleCherrypick(e event, gc githubClient, jc jiraclient.Client, options JiraBranchOptions, log *logrus.Entry) error {
	comment := e.comment(gc)
	var bugs []referencedBug
	if e.cherrypickCmd {
		bugs = e.bugs
	} else {
		// get the info for the PR being cherrypicked from
		pr, err := gc.GetPullRequest(e.org, e.repo, e.cherrypickFromPRNum)
		if err != nil {
			log.WithError(err).Warn("Unexpected error getting title of pull request being cherrypicked from.")
			return comment(fmt.Sprintf("Error creating a cherry-pick bug in Jira: failed to check the state of cherrypicked pull request at https://github.com/%s/%s/pull/%d: %v.\nPlease contact an administrator to resolve this issue, then request a bug refresh with <code>/jira refresh</code>.", e.org, e.repo, e.cherrypickFromPRNum, err))
		}
		// Attempt to identify bug from PR title
		bugs, _, _ = jiraKeyFromTitle(pr.Title)
		if len(bugs) == 0 {
			log.Debugf("Parent PR %d doesn't have associated bug; not creating cherrypicked bug", pr.Number)
			// if there is no jira bug, we should simply ignore this PR
			return nil
		}
	}
	// Since getJira generates a comment itself, we have to add a prefix explaining that this was a cherrypick attempt to the comment
	commentWithPrefix := func(body string) error {
		return comment(fmt.Sprintf("Failed to create a cherry-pick bug in Jira: %s", body))
	}
	msg := ""
	retitleList := make(map[string]string)
refBugLoop:
	for _, refBug := range bugs {
		bug, err := getJira(jc, refBug.Key, log, commentWithPrefix)
		if err != nil || bug == nil {
			return err
		}
		// ignore premerge bugs
		if labels, err := gc.GetIssueLabels(e.org, e.repo, e.number); err != nil {
			log.WithError(err).Warn("Could not list labels on PR")
		} else {
			if isPreMergeVerified(bug, labels) {
				continue
			}
		}
		allowed, err := isBugAllowed(bug, options.AllowedSecurityLevels)
		if err != nil {
			return fmt.Errorf("failed to check is issue is in allowed security level: %w", err)
		}
		if !allowed {
			// ignore bugs that are in non-allowed groups for this repo
			continue
		}
		clones := identifyClones(bug)
		oldLink := fmt.Sprintf(issueLink, refBug.Key, jc.JiraURL(), refBug.Key)
		if options.TargetVersion == nil {
			msg += fmt.Sprintf("Could not make automatic cherrypick of %s for this PR as the target version is not set for this branch in the jira plugin config. Running refresh:\n/jira refresh", oldLink) + "\n\n"
			continue
		}
		targetVersion := *options.TargetVersion
		for _, baseClone := range clones {
			// get full issue struct
			clone, err := jc.GetIssue(baseClone.Key)
			if err != nil {
				return fmt.Errorf("failed to get %s, which is a clone of %s: %w", baseClone.Key, bug.Key, err)
			}
			cloneVersion, err := helpers.GetIssueTargetVersion(clone)
			if err != nil {
				msg += formatError(fmt.Sprintf("getting the target version for clone %s", clone.Key), jc.JiraURL(), bug.Key, err) + "\n\n"
				continue refBugLoop
			}
			if len(cloneVersion) == 1 && cloneVersion[0].Name == targetVersion {
				msg += fmt.Sprintf("Detected clone of %s with correct target version. Will retitle the PR to link to the clone.", oldLink) + "\n\n"
				retitleList[bug.Key] = clone.Key
				continue refBugLoop
			}
		}
		clone, err := jc.CloneIssue(bug)
		if err != nil {
			log.WithError(err).Debugf("Failed to clone bug %+v", bugs)
			msg += formatError("cloning bug for cherrypick", jc.JiraURL(), bug.Key, err) + "\n\n"
			continue
		}
		cloneLink := fmt.Sprintf(issueLink, clone.Key, jc.JiraURL(), clone.Key)
		// add blocking issue link between parent and clone
		blockLink := jira.IssueLink{
			OutwardIssue: &jira.Issue{ID: clone.ID},
			InwardIssue:  &jira.Issue{ID: bug.ID},
			Type: jira.IssueLinkType{
				Name:    "Blocks",
				Inward:  "is blocked by",
				Outward: "blocks",
			},
		}
		if err := jc.CreateIssueLink(&blockLink); err != nil {
			log.WithError(err).Debugf("Unable to create blocks link for bug %s", clone.Key)
			msg += formatError(fmt.Sprintf("updating cherry-pick bug in Jira: Created cherrypick %s, but encountered error creating `Blocks` type link with original bug", cloneLink), jc.JiraURL(), clone.Key, err) + "\n\n"
			continue
		}
		response := fmt.Sprintf("%s has been cloned as %s. Will retitle bug to link to clone.", oldLink, cloneLink)
		retitleList[bug.Key] = clone.Key
		// Update the version of the bug to the target release
		update := jira.Issue{
			Key: clone.Key,
			Fields: &jira.IssueFields{
				Assignee: bug.Fields.Assignee,
				Unknowns: tcontainer.MarshalMap{
					helpers.TargetVersionField: []*jira.Version{{Name: targetVersion}},
				},
			},
		}
		if sprint := helpers.GetSprintField(bug); sprint != nil {
			update.Fields.Unknowns[helpers.SprintField] = sprint
		}
		_, err = jc.UpdateIssue(&update)
		if err != nil {
			response += fmt.Sprintf(`

WARNING: Failed to update the target version for the clone. Please update the target version manually. Full error below:
<details><summary>Full error message.</summary>

<code>
%v
</code>

</details>`, err)
		}
		msg += response + "\n\n"
	}
	msg = strings.TrimSuffix(msg, "\n\n")
	if len(retitleList) > 0 {
		// Replace old bugID(s) in title with new cloneID(s)
		var newTitle string
		if e.cherrypickCmd {
			// use a set to allow sorted keys for deterministic results
			keySet := sets.NewString()
			for _, newBug := range retitleList {
				keySet.Insert(newBug)
			}
			var keyList string
			for _, newBug := range keySet.List() {
				keyList += newBug + ","
			}
			keyList = strings.TrimSuffix(keyList, ",")
			newTitle = fmt.Sprintf("%s: %s", keyList, e.title)
		} else {
			newTitle = e.title
			for oldKey, newKey := range retitleList {
				newTitle = strings.ReplaceAll(newTitle, oldKey, newKey)
			}
		}
		msg += "\n/retitle " + newTitle
	}
	return comment(msg)
}

// return values:
// 1: issues as an array of referencedBug, if exists
// 2: missing: true/false based on whether the title is missing a jira ref
// 3: noJira: true/false based on whether the title contains jira excluding term (i.e. "NO-JIRA" or "NO-ISSUE")
func jiraKeyFromTitle(title string) ([]referencedBug, bool, bool) {
	/*
		// we only match stuff before a ":"
		splitTitle := strings.Split(title, ":")
		if len(splitTitle) < 2 {
			return nil, true, false
		}
		trimmedTitle := splitTitle[0]
		// if there is a space before the `:`,  we ignore this, as the title is improperly formatted
		if string(trimmedTitle[len(trimmedTitle)-1]) == " " {
			return nil, true, false
		}
		// if there are square brackets, remove them and everything between them
		leftBracket := strings.Index(title, "[")
		rightBracket := strings.Index(title, "]")
		if rightBracket-leftBracket != 0 {
			trimmedTitle = trimmedTitle[0:leftBracket] + trimmedTitle[rightBracket+1:]
		}
	*/
	matches := titleMatchJiraIssue.FindString(title)
	if len(matches) == 0 {
		return nil, true, false
	}
	bugs := []referencedBug{}
	splitMatch := strings.Split(matches, ",")
	for _, match := range splitMatch {
		match = strings.TrimSuffix(match, ":")
		if strings.EqualFold(match, "NO-ISSUE") || strings.EqualFold(match, "NO-JIRA") {
			return nil, false, true
		}
		bugs = append(bugs, referencedBug{
			Key:   match,
			IsBug: strings.Contains(match, "OCPBUGS-"),
		})
	}
	return bugs, false, false
}

func getJira(jc jiraclient.Client, jiraKey string, log *logrus.Entry, comment func(string) error) (*jira.Issue, error) {
	issue, err := jc.GetIssue(jiraKey)
	if err != nil && !jiraclient.IsNotFound(err) {
		log.WithError(err).Warn("Unexpected error searching for Jira issue.")
		return nil, comment(formatError("searching", jc.JiraURL(), jiraKey, err))
	}
	if jiraclient.IsNotFound(err) || issue == nil {
		log.Debug("No jira issue found.")
		return nil, comment(fmt.Sprintf(`No Jira issue with key %s exists in the tracker at %s.
Once a valid jira issue is referenced in the title of this pull request, request a refresh with <code>/jira refresh</code>.`,
			jiraKey, jc.JiraURL()))
	}
	return issue, nil
}

func formatError(action, endpoint, bugKey string, err error) string {
	knownErrors := map[string]string{
		// TODO: Most of this code is copied from the bugzilla client. If Jira rate limits us the same way, this could come in handy. We will keep this for now in case it is needed
		//"There was an error reported for a GitHub REST call": "The Bugzilla server failed to load data from GitHub when creating the bug. This is usually caused by rate-limiting, please try again later.",
	}
	var applicable []string
	for key, value := range knownErrors {
		if strings.Contains(err.Error(), key) {
			applicable = append(applicable, value)
		}
	}
	digest := "No known errors were detected, please see the full error message for details."
	if len(applicable) > 0 {
		digest = "We were able to detect the following conditions from the error:\n\n"
		for _, item := range applicable {
			digest = fmt.Sprintf("%s- %s\n", digest, item)
		}
	}
	return fmt.Sprintf(`An error was encountered %s for bug %s on the Jira server at %s. %s

<details><summary>Full error message.</summary>

<code>
%v
</code>

</details>

Please contact an administrator to resolve this issue, then request a bug refresh with <code>/jira refresh</code>.`,
		action, bugKey, endpoint, digest, err)
}

var PrivateVisibility = jira.CommentVisibility{Type: "group", Value: "Red Hat Employee"}

func handleClose(e event, gc githubClient, jc jiraclient.Client, options JiraBranchOptions, log *logrus.Entry) error {
	comment := e.comment(gc)
	if e.missing {
		return nil
	}
	msg := ""
	for _, refBug := range e.bugs {
		if !refBug.IsBug {
			return nil
		}
		if options.AddExternalLink != nil && *options.AddExternalLink {
			response := fmt.Sprintf(`This pull request references `+issueLink+`. The bug has been updated to no longer refer to the pull request using the external bug tracker.`, refBug.Key, jc.JiraURL(), refBug.Key)
			changed, err := jc.DeleteRemoteLinkViaURL(refBug.Key, prURLFromCommentURL(e.htmlUrl))
			if err != nil && !strings.HasPrefix(err.Error(), "could not find remote link on issue with URL") {
				log.WithError(err).Warn("Unexpected error removing external tracker bug from Jira bug.")
				msg += formatError("removing this pull request from the external tracker bugs", jc.JiraURL(), refBug.Key, err) + "\n\n"
				continue
			}
			if options.StateAfterClose != nil || options.PreMergeStateAfterClose != nil {
				issue, err := jc.GetIssue(refBug.Key)
				if err != nil {
					log.WithError(err).Warn("Unexpected error getting Jira issue.")
					msg += formatError("getting issue", jc.JiraURL(), refBug.Key, err) + "\n\n"
					continue
				}
				if !strings.EqualFold(issue.Fields.Status.Name, status.Closed) {
					links, err := jc.GetRemoteLinks(issue.ID)
					if err != nil {
						log.WithError(err).Warn("Unexpected error getting remote links for Jira issue.")
						msg += formatError("getting remote links", jc.JiraURL(), refBug.Key, err) + "\n\n"
						continue
					}
					if len(links) == 0 {
						bug, err := getJira(jc, refBug.Key, log, comment)
						if err != nil || bug == nil {
							return err
						}
						premergeVerified := false
						if labels, err := gc.GetIssueLabels(e.org, e.repo, e.number); err != nil {
							log.WithError(err).Warn("Could not list labels on PR")
						} else {
							premergeVerified = isPreMergeVerified(bug, labels)
						}
						updatedState := JiraBugState{}
						if premergeVerified {
							updatedState = JiraBugState{Status: options.PreMergeStateAfterClose.Status, Resolution: options.PreMergeStateAfterClose.Resolution}
							if options.PreMergeStateAfterClose.Status != "" && (bug.Fields.Status == nil || !strings.EqualFold(options.PreMergeStateAfterClose.Status, bug.Fields.Status.Name)) {
								if err := jc.UpdateStatus(issue.ID, options.PreMergeStateAfterClose.Status); err != nil {
									log.WithError(err).Warn("Unexpected error updating jira issue.")
									msg += formatError(fmt.Sprintf("updating to the %s state", options.PreMergeStateAfterClose.Status), jc.JiraURL(), refBug.Key, err) + "\n\n"
									continue
								}
								if options.PreMergeStateAfterClose.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(options.PreMergeStateAfterClose.Resolution, bug.Fields.Resolution.Name)) {
									updateIssue := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.PreMergeStateAfterClose.Resolution}}}
									if _, err := jc.UpdateIssue(&updateIssue); err != nil {
										log.WithError(err).Warn("Unexpected error updating jira issue.")
										msg += formatError(fmt.Sprintf("updating to the %s resolution", options.PreMergeStateAfterClose.Resolution), jc.JiraURL(), refBug.Key, err) + "\n\n"
										continue
									}
								}
							}
						} else {
							updatedState = JiraBugState{Status: options.StateAfterClose.Status, Resolution: options.StateAfterClose.Resolution}
							if options.StateAfterClose.Status != "" && (bug.Fields.Status == nil || !strings.EqualFold(options.StateAfterClose.Status, bug.Fields.Status.Name)) {
								if err := jc.UpdateStatus(issue.ID, options.StateAfterClose.Status); err != nil {
									log.WithError(err).Warn("Unexpected error updating jira issue.")
									msg += formatError(fmt.Sprintf("updating to the %s state", options.StateAfterClose.Status), jc.JiraURL(), refBug.Key, err) + "\n\n"
									continue
								}
								if options.StateAfterClose.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(options.StateAfterClose.Resolution, bug.Fields.Resolution.Name)) {
									updateIssue := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.StateAfterClose.Resolution}}}
									if _, err := jc.UpdateIssue(&updateIssue); err != nil {
										log.WithError(err).Warn("Unexpected error updating jira issue.")
										msg += formatError(fmt.Sprintf("updating to the %s resolution", options.StateAfterClose.Resolution), jc.JiraURL(), refBug.Key, err) + "\n\n"
										continue
									}
								}
							}
						}
						response += fmt.Sprintf(" All external bug links have been closed. The bug has been moved to the %s state.", PrettyStatus(updatedState.Status, updatedState.Resolution))
						jiraComment := &jira.Comment{Body: fmt.Sprintf("Bug status changed to %s as previous linked PR https://github.com/%s/%s/pull/%d has been closed", options.StateAfterClose.Status, e.org, e.repo, e.number), Visibility: PrivateVisibility}
						if _, err := jc.AddComment(bug.ID, jiraComment); err != nil {
							response += "\nWarning: Failed to comment on Jira bug with reason for changed state."
						}
					}
				}
			}
			if changed {
				msg += response + "\n\n"
			}
		}
	}
	if len(msg) != 0 {
		msg = strings.TrimSuffix(msg, "\n\n")
		return comment(msg)
	}
	return nil
}

func isBugAllowed(issue *jira.Issue, allowedSecurityLevel []string) (bool, error) {
	// if no allowed visibilities are listed, assume all visibilities are allowed
	if len(allowedSecurityLevel) == 0 {
		return true, nil
	}

	level, err := helpers.GetIssueSecurityLevel(issue)
	if err != nil {
		return false, fmt.Errorf("failed to get security level: %w", err)
	}
	if level == nil {
		// default security level is empty; make a temporary "default" security level for this check
		level = &helpers.SecurityLevel{Name: "default"}
	}
	found := false
	for _, allowed := range allowedSecurityLevel {
		if level.Name == allowed {
			found = true
			break
		}
	}
	return found, nil
}

func checkTargetVersion(options JiraBranchOptions) bool {
	switch {
	case options.SkipTargetVersionCheck != nil && *options.SkipTargetVersionCheck:
		return false
	case options.TargetVersion != nil:
		return true
	default:
		return false
	}
}
