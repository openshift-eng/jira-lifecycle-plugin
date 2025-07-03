package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andygrunwald/go-jira"
	githubql "github.com/shurcooL/githubv4"
	"github.com/sirupsen/logrus"
	"github.com/trivago/tgo/tcontainer"

	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/prow/pkg/config"
	"sigs.k8s.io/prow/pkg/github"
	jiraclient "sigs.k8s.io/prow/pkg/jira"
	"sigs.k8s.io/prow/pkg/pluginhelp"
	"sigs.k8s.io/prow/pkg/plugins"

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
	jiraIssueRegexPart       = `[[:alnum:]]+-[[:digit:]]+`
	titleMatchJiraIssue      = regexp.MustCompile(`(?i)(` + jiraIssueRegexPart + `,?[[:space:]]*)*(NO-JIRA|NO-ISSUE|` + jiraIssueRegexPart + `)+:`)
	verifyCommandMatch       = regexp.MustCompile(`(?mi)^/verified by\s+(([^\s]+,)*([^\s]+))*$`)
	verifyRemoveCommandMatch = regexp.MustCompile(`(?mi)^/verified remove$`)
	verifyLaterCommandMatch  = regexp.MustCompile(`(?mi)^/verified later\s+(([^\s]+,)*([^\s]+))*$`)
	refreshCommandMatch      = regexp.MustCompile(`(?mi)^/jira refresh\s*$`)
	qaReviewCommandMatch     = regexp.MustCompile(`(?mi)^/jira cc-qa\s*$`)
	cherrypickCommandMatch   = regexp.MustCompile(`(?mi)^/jira cherry-?pick (` + jiraIssueRegexPart + `,?[[:space:]]*)*(` + jiraIssueRegexPart + `)+\s*$`)
	backportCommandMatch     = regexp.MustCompile(`(?mi)^/jira backport\s+(([^\s]+,)*([^\s]+))$`)
	existingBackportMatch    = regexp.MustCompile(`jlp-[^:]+:[^:]+`)
	cherrypickPRMatch        = regexp.MustCompile(`This is an automated cherry-pick of #([0-9]+)`)
	jiraIssueReferenceMatch  = regexp.MustCompile(`([[:alnum:]]+)-([[:digit:]]+)`)
	bugProjects              = sets.New("OCPBUGS", "DFBUGS")
)

type referencedIssue struct {
	Project string
	ID      string
	IsBug   bool
}

func (i referencedIssue) Key() string {
	return fmt.Sprintf("%s-%s", i.Project, i.ID)
}

type dependent struct {
	key              string
	targetVersion    *string
	multipleVersions bool
	bugState         JiraBugState
}

type server struct {
	config func() *Config

	prowConfigAgent *config.Agent
	ghc             githubClient
	jc              jiraclient.Client

	bigqueryInserter BigQueryInserter
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
	QueryWithGitHubAppsSupport(ctx context.Context, q any, vars map[string]any, org string) error
	BotUserChecker() (func(candidate string) bool, error)
}

func (s *server) handleIssueComment(l *logrus.Entry, e github.IssueCommentEvent) {
	cfg := s.config()
	event, err := digestComment(s.ghc, l, e)
	if err != nil {
		l.Errorf("failed to digest comment: %v", err)
	}
	if event != nil {
		branchOptions := cfg.OptionsForBranch(event.org, event.repo, event.baseRef)
		repoOptions := cfg.OptionsForRepo(event.org, event.repo)
		if err := handle(s.jc, s.ghc, s.bigqueryInserter, repoOptions, branchOptions, l, *event, s.prowConfigAgent.Config().AllRepos); err != nil {
			l.Errorf("failed to handle comment: %v", err)
		}
	}
}

func handle(jc jiraclient.Client, ghc githubClient, inserter BigQueryInserter, repoOptions map[string]JiraBranchOptions, branchOptions JiraBranchOptions, log *logrus.Entry, e event, allRepos sets.Set[string]) error {
	comment := e.comment(ghc)
	if !e.missing {
		for _, refIssue := range e.issues {
			if refIssue.IsBug && refIssue.Key() != "" {
				issue, err := getJira(jc, refIssue.Key(), log, comment)
				if err != nil || issue == nil {
					return err
				}
				bugAllowed, err := isBugAllowed(issue, branchOptions.AllowedSecurityLevels)
				if err != nil {
					return err
				}
				if !bugAllowed {
					// ignore bugs that are in non-allowed security levels for this repo
					if e.opened || e.refresh {
						response := fmt.Sprintf(issueLink+" is in a security level that is not in the allowed security levels for this repo.", refIssue.Key(), jc.JiraURL(), refIssue.Key())
						if len(branchOptions.AllowedSecurityLevels) > 0 {
							response += "\nAllowed security levels for this repo are:"
							for _, group := range branchOptions.AllowedSecurityLevels {
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
	// just remove verified label if files were changed
	if e.fileChanged {
		currentLabels, err := ghc.GetIssueLabels(e.org, e.repo, e.number)
		if err != nil {
			log.WithError(err).Warn("Could not list labels on PR")
		}
		for _, label := range currentLabels {
			if label.Name == labels.Verified {
				if err := ghc.RemoveLabel(e.org, e.repo, e.number, labels.Verified); err != nil {
					log.WithError(err).Error("Failed to remove verified label.")
				}
				info := VerificationInfo{
					User:      e.login,
					Reason:    "modified",
					Type:      verifyRemoveType,
					Org:       e.org,
					Repo:      e.repo,
					PRNum:     e.number,
					Branch:    e.baseRef,
					Timestamp: time.Now(),
				}
				if err := inserter.Put(context.TODO(), info); err != nil {
					log.WithError(err).Error("Failed to upload info to Big Query")
				}
			} else if label.Name == labels.VerifiedLater {
				if err := ghc.RemoveLabel(e.org, e.repo, e.number, labels.VerifiedLater); err != nil {
					log.WithError(err).Error("Failed to remove verified-later label.")
				}
				info := VerificationInfo{
					User:      e.login,
					Reason:    "modified",
					Type:      verifyRemoveLaterType,
					Org:       e.org,
					Repo:      e.repo,
					PRNum:     e.number,
					Branch:    e.baseRef,
					Timestamp: time.Now(),
				}
				if err := inserter.Put(context.TODO(), info); err != nil {
					log.WithError(err).Error("Failed to upload info to Big Query")
				}
			}
		}
		return nil
	}
	// cherrypicks follow a different pattern than normal validation
	if e.cherrypick {
		return handleCherrypick(e, ghc, jc, branchOptions, log)
	}
	if e.backport {
		return handleBackport(e, ghc, jc, repoOptions, log)
	}
	// merges follow a different pattern from the normal validation
	if e.merged {
		return handleMerge(e, ghc, jc, branchOptions, log, allRepos)
	}
	// close events follow a different pattern from the normal validation
	if e.closed && !e.merged {
		return handleClose(e, ghc, jc, branchOptions, log)
	}
	// verification commands follow a different pattern than normal validation
	if len(e.verify) > 0 || len(e.verifyLater) > 0 || e.verifiedRemove {
		return handleVerification(e, ghc, inserter, log)
	}

	var needsJiraValidRefLabel, needsJiraValidBugLabel, needsJiraInvalidBugLabel bool
	var response, severityLabel string
	var invalidIssues []string
	if !e.noJira {
		for _, refIssue := range e.issues {
			// separate responses for different bugs
			if response != "" {
				response += "\n\n"
			}
			var issue *jira.Issue
			var err error
			if !e.missing {
				issue, err = getJira(jc, refIssue.Key(), log, comment)
				if err != nil {
					return err
				}
			}

			if issue == nil {
				invalidIssues = append(invalidIssues, refIssue.Key())
			} else {
				needsJiraValidRefLabel = true
				premergeUpdated := false
				// check labels for premerge verification
				if refIssue.IsBug {
					if labels, err := ghc.GetIssueLabels(e.org, e.repo, e.number); err != nil {
						log.WithError(err).Warn("Could not list labels on PR")
					} else {
						premergeVerified := isPreMergeVerified(issue, labels)
						if premergeVerified && branchOptions.PreMergeStateAfterValidation != nil {
							if branchOptions.PreMergeStateAfterValidation.Status != "" && (issue.Fields.Status == nil || !strings.EqualFold(issue.Fields.Status.Name, branchOptions.PreMergeStateAfterValidation.Status)) {
								if err := jc.UpdateStatus(issue.Key, branchOptions.PreMergeStateAfterValidation.Status); err != nil {
									log.WithError(err).Warn("Unexpected error updating jira issue.")
									response += formatError(fmt.Sprintf("updating to the %s state", branchOptions.PreMergeStateAfterValidation.Status), jc.JiraURL(), refIssue.Key(), err)
									continue
								}
								premergeUpdated = true
							}
							if branchOptions.PreMergeStateAfterValidation.Resolution != "" && (issue.Fields.Resolution == nil || !strings.EqualFold(issue.Fields.Status.Name, branchOptions.PreMergeStateAfterValidation.Resolution)) {
								updateIssue := jira.Issue{Key: issue.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: branchOptions.PreMergeStateAfterValidation.Resolution}}}
								if _, err := jc.UpdateIssue(&updateIssue); err != nil {
									log.WithError(err).Warn("Unexpected error updating jira issue.")
									response += formatError(fmt.Sprintf("updating to the %s resolution", branchOptions.PreMergeStateAfterMerge.Resolution), jc.JiraURL(), refIssue.Key(), err)
									continue
								}
								premergeUpdated = true
							}
						}
						// if this is a premerge verified issue, we don't want to run the usual verification on it; just treat it as a reference instead
						refIssue.IsBug = !premergeVerified
					}
				}
				if !refIssue.IsBug {
					// don't linkify the jira ref in this case because the prow-jira plugin will do so and we don't want it to
					// end up double-linkified.  The prow-jira plugin should be configured to not linkify bugProjects refs, but it will
					// linkify refs to other projects.
					response += fmt.Sprintf("This pull request references %s which is a valid jira issue.", refIssue.Key())
					if premergeUpdated {
						response += fmt.Sprintf(" The bug has been moved to the %s state.", PrettyStatus(branchOptions.PreMergeStateAfterValidation.Status, branchOptions.PreMergeStateAfterValidation.Resolution))
					}
					// We still want to notify if the pull request branch and bug target version mismatch
					if checkTargetVersion(branchOptions) {
						if err := validateTargetVersion(issue, *branchOptions.TargetVersion); err != nil {
							response += fmt.Sprintf("\n\nWarning: The referenced jira issue has an invalid target version for the target branch this PR targets: %v.", err)
						}
					}
				}
			}
			if refIssue.IsBug && issue != nil {
				log = log.WithField("refKey", refIssue.Key())

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
				if branchOptions.DependentBugStates != nil || branchOptions.DependentBugTargetVersions != nil {
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
							return comment(formatError(fmt.Sprintf("searching for dependent bug %s", linkIssue.Key), jc.JiraURL(), refIssue.Key(), err))
						}
						targetVersion, err := helpers.GetIssueTargetVersion(dependentIssue)
						if err != nil {
							return comment(formatError(fmt.Sprintf("failed to get target version for %s", dependentIssue.Key), jc.JiraURL(), refIssue.Key(), err))
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

				valid, passes, fails := validateBug(issue, dependents, branchOptions, jc.JiraURL())
				if !needsJiraInvalidBugLabel {
					needsJiraValidBugLabel, needsJiraInvalidBugLabel = valid, !valid
				}
				if valid {
					log.Debug("Valid bug found.")
					response += fmt.Sprintf(`This pull request references `+issueLink+`, which is valid.`, refIssue.Key(), jc.JiraURL(), refIssue.Key())
					// if configured, move the bug to the new state
					if branchOptions.StateAfterValidation != nil {
						if branchOptions.StateAfterValidation.Status != "" && (issue.Fields.Status == nil || !strings.EqualFold(branchOptions.StateAfterValidation.Status, issue.Fields.Status.Name)) {
							if err := jc.UpdateStatus(issue.ID, branchOptions.StateAfterValidation.Status); err != nil {
								log.WithError(err).Warn("Unexpected error updating jira issue.")
								return comment(formatError(fmt.Sprintf("updating to the %s state", branchOptions.StateAfterValidation.Status), jc.JiraURL(), refIssue.Key(), err))
							}
							if branchOptions.StateAfterValidation.Resolution != "" && (issue.Fields.Resolution == nil || !strings.EqualFold(branchOptions.StateAfterValidation.Resolution, issue.Fields.Resolution.Name)) {
								updateIssue := jira.Issue{Key: issue.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: branchOptions.StateAfterValidation.Resolution}}}
								if _, err := jc.UpdateIssue(&updateIssue); err != nil {
									log.WithError(err).Warn("Unexpected error updating jira issue.")
									return comment(formatError(fmt.Sprintf("updating to the %s resolution", branchOptions.StateAfterValidation.Resolution), jc.JiraURL(), refIssue.Key(), err))
								}
							}
							response += fmt.Sprintf(" The bug has been moved to the %s state.", branchOptions.StateAfterValidation)
						}
					}

					response += "\n\n<details>"
					if len(passes) == 0 {
						response += "<summary>No validations were run on this bug</summary>"
					} else {
						response += fmt.Sprintf("<summary>%d validation(s) were run on this bug</summary>\n", len(passes))
					}
					for _, validation := range passes {
						response += fmt.Sprint("\n* ", validation)
					}
					response += "</details>"

					qaContactDetail, err := helpers.GetIssueQaContact(issue)
					if err != nil {
						return comment(formatError("processing qa contact information for the bug", jc.JiraURL(), refIssue.Key(), err))
					}
					if qaContactDetail == nil {
						if e.cc {
							response += fmt.Sprintf(issueLink+" does not have a QA contact, skipping assignment", refIssue.Key(), jc.JiraURL(), refIssue.Key())
						}
					} else if qaContactDetail.EmailAddress == "" {
						if e.cc {
							response += fmt.Sprintf("QA contact for "+issueLink+" does not have a listed email, skipping assignment", refIssue.Key(), jc.JiraURL(), refIssue.Key())
						}
					} else {
						query := &emailToLoginQuery{}
						email := qaContactDetail.EmailAddress
						queryVars := map[string]any{
							"email": githubql.String(email),
						}
						err := ghc.QueryWithGitHubAppsSupport(context.Background(), query, queryVars, e.org)
						if err != nil {
							log.WithError(err).Error("Failed to run graphql github query")
							return comment(formatError(fmt.Sprintf("querying GitHub for users with public email (%s)", email), jc.JiraURL(), refIssue.Key(), err))
						}
						response += fmt.Sprint("\n\n", processQuery(query, email))
					}
				} else {
					log.Debug("Invalid bug found.")
					var formattedReasons string
					for _, reason := range fails {
						formattedReasons += fmt.Sprintf(" - %s\n", reason)
					}
					response += fmt.Sprintf(`This pull request references `+issueLink+`, which is invalid:
%s
Comment <code>/jira refresh</code> to re-evaluate validity if changes to the Jira bug are made, or edit the title of this pull request to link to a different bug.`, refIssue.Key(), jc.JiraURL(), refIssue.Key(), formattedReasons)
				}

				if branchOptions.AddExternalLink != nil && *branchOptions.AddExternalLink {
					changed, err := upsertGitHubLinkToIssue(log, issue.ID, jc, e)
					if err != nil {
						log.WithError(err).Warn("Unexpected error adding external tracker bug to Jira bug.")
						return comment(formatError("adding this pull request to the external tracker bugs", jc.JiraURL(), refIssue.Key(), err))
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
		return "", fmt.Errorf("failed to get severity of issue %s", issue.Key)
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

func isCommentVerified(prLabels []github.Label) bool {
	for _, label := range prLabels {
		if label.Name == labels.Verified {
			return true
		}
	}
	return false
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
	branchOptions := cfg.OptionsForBranch(pre.PullRequest.Base.Repo.Owner.Login, pre.PullRequest.Base.Repo.Name, pre.PullRequest.Base.Ref)
	event, err := digestPR(l, pre, branchOptions.ValidateByDefault)
	if err != nil {
		l.Errorf("failed to digest PR: %v", err)
	}
	if event != nil {
		repoOptions := cfg.OptionsForRepo(event.org, event.repo)
		if err := handle(s.jc, s.ghc, s.bigqueryInserter, repoOptions, branchOptions, l, *event, s.prowConfigAgent.Config().AllRepos); err != nil {
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
			return false, 0, fmt.Errorf("failed to parse cherrypick jira issue - is the regex correct? Err: %w", err)
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
		pre.Action != github.PullRequestActionUnlabeled &&
		pre.Action != github.PullRequestActionSynchronize {
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

	e := &event{org: org, repo: repo, baseRef: baseRef, number: number, merged: pre.PullRequest.Merged, closed: pre.Action == github.PullRequestActionClosed, opened: pre.Action == github.PullRequestActionOpened, state: pre.PullRequest.State, body: body, title: title, htmlUrl: pre.PullRequest.HTMLURL, login: pre.PullRequest.User.Login, fileChanged: pre.Action == github.PullRequestActionSynchronize}
	// Make sure the PR title is referencing a bug
	var err error
	e.issues, e.missing, e.noJira = jiraKeyFromTitle(title)

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
	if len(prevIds) == len(e.issues) {
		var changed bool
		for index, prevBug := range prevIds {
			if e.issues[index].Key() != prevBug.Key() {
				changed = true
				break
			}
		}
		if !changed {
			logrus.Debugf("Referenced Jira issue(s) (%+v) has not changed, not handling event.", e.issues)
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
	var refresh, cc, cherrypick, backport, verifiedRemove bool
	var verified, verifyLater []string
	switch {
	case refreshCommandMatch.MatchString(ice.Comment.Body):
		refresh = true
	case qaReviewCommandMatch.MatchString(ice.Comment.Body):
		cc = true
	case cherrypickCommandMatch.MatchString(ice.Comment.Body):
		cherrypick = true
	case backportCommandMatch.MatchString(ice.Comment.Body):
		backport = true
	case verifyCommandMatch.MatchString(ice.Comment.Body):
		var err error
		verified, err = verifyCommandMatches(ice.Comment.Body)
		if err != nil {
			return nil, err
		}
	case verifyLaterCommandMatch.MatchString(ice.Comment.Body):
		var err error
		verifyLater, err = verifyLaterCommandMatches(ice.Comment.Body)
		if err != nil {
			return nil, err
		}
	case verifyRemoveCommandMatch.MatchString(ice.Comment.Body):
		verifiedRemove = true
	default:
		return nil, nil
	}
	var (
		org    = ice.Repo.Owner.Login
		repo   = ice.Repo.Name
		number = ice.Issue.Number
	)

	// We don't support linking issues to bugProjects
	if !ice.Issue.IsPullRequest() {
		log.Debug("Jira bug command requested on an issue, ignoring")
		return nil, gc.CreateComment(org, repo, number, formatResponseRaw(ice.Comment.Body, ice.Comment.HTMLURL, ice.Comment.User.Login, `Jira bug referencing is only supported for Pull Requests, not issues.`, fmt.Sprintf("%s/%s", ice.Repo.Owner.Login, ice.Repo.Name)))
	}

	// Make sure the PR title is referencing a bug
	pr, err := gc.GetPullRequest(org, repo, number)
	if err != nil {
		return nil, err
	}

	e := &event{
		org:            org,
		repo:           repo,
		baseRef:        pr.Base.Ref,
		number:         number,
		merged:         pr.Merged,
		state:          pr.State,
		body:           ice.Comment.Body,
		title:          ice.Issue.Title,
		htmlUrl:        ice.Comment.HTMLURL,
		login:          ice.Comment.User.Login,
		refresh:        refresh,
		cc:             cc,
		verify:         verified,
		verifyLater:    verifyLater,
		verifiedRemove: verifiedRemove,
	}

	e.issues, e.missing, e.noJira = jiraKeyFromTitle(pr.Title)

	if cherrypick {
		var matchError error
		e.issues, matchError = cherryPickCommandMatches(ice.Comment.Body)
		if matchError != nil {
			return nil, matchError
		}
		e.cherrypick = true
		e.cherrypickCmd = true
	}

	if backport {
		var matchError error
		e.backportBranches, matchError = backportCommandMatches(ice.Comment.Body)
		if matchError != nil {
			return nil, matchError
		}
		e.backport = true
	}

	return e, nil
}

func cherryPickCommandMatches(body string) ([]referencedIssue, error) {
	commandMatches := cherrypickCommandMatch.FindStringSubmatch(body)
	if len(commandMatches) == 0 {
		return nil, fmt.Errorf("body %q did not match cherry-pick regex, programmer error", body)
	}
	return referencedIssues(commandMatches[0]), nil
}

func backportCommandMatches(body string) ([]string, error) {
	commandMatches := backportCommandMatch.FindAllStringSubmatch(body, -1)
	if len(commandMatches) == 0 || len(commandMatches[0]) < 2 {
		return nil, fmt.Errorf("body %q did not match backport regex, programmer error", body)
	}
	return strings.Split(commandMatches[0][1], ","), nil
}

func verifyCommandMatches(body string) ([]string, error) {
	commandMatches := verifyCommandMatch.FindAllStringSubmatch(body, -1)
	if len(commandMatches) == 0 || len(commandMatches[0]) < 2 {
		return nil, fmt.Errorf("body %q did not match verify regex, programmer error", body)
	}
	return strings.Split(commandMatches[0][1], ","), nil
}

func verifyLaterCommandMatches(body string) ([]string, error) {
	commandMatches := verifyLaterCommandMatch.FindAllStringSubmatch(body, -1)
	if len(commandMatches) == 0 || len(commandMatches[0]) < 2 {
		return nil, fmt.Errorf("body %q did not match verify-later regex, programmer error", body)
	}
	return strings.Split(commandMatches[0][1], ","), nil
}

func referencedIssues(matchingText string) []referencedIssue {
	matches := jiraIssueReferenceMatch.FindAllStringSubmatch(matchingText, -1)
	var issues []referencedIssue
	for _, match := range matches {
		issues = append(issues, referencedIssue{
			Project: match[1],
			ID:      match[2],
			IsBug:   bugProjects.Has(match[1]),
		})
	}
	return issues
}

type event struct {
	org, repo, baseRef              string
	number                          int
	issues                          []referencedIssue
	noJira                          bool
	missing, merged, closed, opened bool
	state                           string
	body, title, htmlUrl, login     string
	refresh, cc, cherrypickCmd      bool
	cherrypick                      bool
	cherrypickFromPRNum             int
	backport                        bool
	backportBranches                []string
	verify, verifyLater             []string
	verifiedRemove, fileChanged     bool
}

func (e *event) comment(gc githubClient) func(body string) error {
	return func(body string) error {
		return gc.CreateComment(e.org, e.repo, e.number, formatResponseRaw(e.body, e.htmlUrl, e.login, body, fmt.Sprintf("%s/%s", e.org, e.repo)))
	}
}

// formatResponseRaw nicely formats a response for one does not have an issue comment
func formatResponseRaw(body, bodyURL, login, reply, orgRepo string) string {
	format := `In response to [this](%s):

%s
`
	// Quote the user's comment by prepending ">" to each line.
	var quoted []string
	for _, l := range strings.Split(body, "\n") {
		quoted = append(quoted, ">"+l)
	}
	return formatResponse(login, reply, fmt.Sprintf(format, bodyURL, strings.Join(quoted, "\n")), orgRepo)
}

// formatResponse nicely formats a response to a generic reason.
func formatResponse(to, message, reason, orgRepo string) string {
	helpURL := url.URL{
		Scheme: "https",
		Host:   "prow.ci.openshift.org",
		Path:   "command-help",
	}
	query := helpURL.Query()
	query.Add("repo", orgRepo)
	helpURL.RawQuery = query.Encode()
	format := `@%s: %s

<details>

%s

Instructions for interacting with me using PR comments are available [here](%s).  If you have questions or suggestions related to my behavior, please file an issue against the [openshift-eng/jira-lifecycle-plugin](https://github.com/openshift-eng/jira-lifecycle-plugin/issues/new) repository.
</details>`

	return fmt.Sprintf(format, to, message, reason, helpURL.String())
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
func processQuery(query *emailToLoginQuery, email string) string {
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
	var passes []string
	var fails []string
	if options.IsOpen != nil && (bug.Fields == nil || bug.Fields.Status == nil || *options.IsOpen != !strings.EqualFold(bug.Fields.Status.Name, status.Closed)) {
		valid = false
		not := ""
		was := "isn't"
		if !*options.IsOpen {
			not = "not "
			was = "is"
		}
		fails = append(fails, fmt.Sprintf("expected the bug to %sbe open, but it %s", not, was))
	} else if options.IsOpen != nil {
		expected := "open"
		if !*options.IsOpen {
			expected = "not open"
		}
		was := "isn't"
		if !strings.EqualFold(bug.Fields.Status.Name, status.Closed) {
			was = "is"
		}
		passes = append(passes, fmt.Sprintf("bug %s open, matching expected state (%s)", was, expected))
	}

	if options.TargetVersion != nil {
		if err := validateTargetVersion(bug, *options.TargetVersion); err != nil {
			fails = append(fails, err.Error())
			valid = false
		} else {
			passes = append(passes, fmt.Sprintf("bug target version (%s) matches configured target version for branch (%s)", *options.TargetVersion, *options.TargetVersion))
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
			fails = append(fails, fmt.Sprintf("expected the bug to be in one of the following states: %s, but it is %s instead", strings.Join(prettyStates(allowed), ", "), PrettyStatus(status, resolution)))
		} else {
			passes = append(passes, fmt.Sprintf("bug is in the state %s, which is one of the valid states (%s)", PrettyStatus(status, resolution), strings.Join(prettyStates(allowed), ", ")))
		}
	}

	if options.RequireReleaseNotes != nil && *options.RequireReleaseNotes {
		releaseNoteType, err := helpers.GetIssueReleaseNoteType(bug)
		if err != nil {
			fails = append(fails, err.Error())
		}
		releaseNotes, err := helpers.GetIssueReleaseNoteText(bug)
		if err != nil {
			fails = append(fails, err.Error())
			valid = false
		} else {
			if (releaseNotes == nil || *releaseNotes == "" || (options.ReleaseNotesDefaultText != nil && *options.ReleaseNotesDefaultText == *releaseNotes)) && (releaseNoteType == nil || releaseNoteType.Value != "Release Note Not Required") {
				valid = false
				fails = append(fails, "release note text must be set and not match the template OR release note type must be set to \"Release Note Not Required\".  For more information you can reference the [OpenShift Bug Process](https://source.redhat.com/groups/public/openshift/openshift_wiki/openshift_bugzilla_process#doc-text-for-bugs).")
			} else {
				if releaseNotes != nil && *releaseNotes != "" {
					passes = append(passes, "release note text is set and does not match the template")
				} else if releaseNoteType != nil && releaseNoteType.Value == "Release Note Not Required" {
					passes = append(passes, "release note type set to \"Release Note Not Required\"")
				} else {
					// this else shouldn't be triggered, but it should still set the validation in case something was missed or changes above
					passes = append(passes, "release notes fields are valid")
				}
			}
		}
	}

	if options.DependentBugStates != nil {
		for _, depBug := range dependents {
			if bug.Fields != nil {
				if !strings.HasPrefix(depBug.key, bug.Fields.Project.Key+"-") {
					continue
				}
			} else {
				// this should never happen
				fails = append(fails, fmt.Sprintf("unable to identify project for issue %s", depBug.key))
			}
			if !depBug.bugState.matches(*options.DependentBugStates) {
				valid = false
				expected := strings.Join(prettyStates(*options.DependentBugStates), ", ")
				actual := PrettyStatus(depBug.bugState.Status, depBug.bugState.Resolution)
				fails = append(fails, fmt.Sprintf("expected dependent "+issueLink+" to be in one of the following states: %s, but it is %s instead", depBug.key, jiraEndpoint, depBug.key, expected, actual))
			} else {
				passes = append(passes, fmt.Sprintf("dependent bug "+issueLink+" is in the state %s, which is one of the valid states (%s)", depBug.key, jiraEndpoint, depBug.key, PrettyStatus(depBug.bugState.Status, depBug.bugState.Resolution), strings.Join(prettyStates(*options.DependentBugStates), ", ")))
			}
		}
	}

	if options.DependentBugTargetVersions != nil {
		for _, depBug := range dependents {
			if bug.Fields != nil {
				if !strings.HasPrefix(depBug.key, bug.Fields.Project.Key+"-") {
					continue
				}
			} else {
				// this should never happen
				fails = append(fails, fmt.Sprintf("unable to identify project for issue %s", depBug.key))
			}
			if depBug.targetVersion == nil {
				valid = false
				fails = append(fails, fmt.Sprintf("expected dependent "+issueLink+" to target a version in %s, but no target version was set", depBug.key, jiraEndpoint, depBug.key, strings.Join(*options.DependentBugTargetVersions, ", ")))
			} else if depBug.multipleVersions {
				valid = false
				fails = append(fails, fmt.Sprintf("expected dependent "+issueLink+" to target a version in %s, but it has multiple target versions", depBug.key, jiraEndpoint, depBug.key, strings.Join(*options.DependentBugTargetVersions, ", ")))
			} else if sets.NewString(*options.DependentBugTargetVersions...).Has(*depBug.targetVersion) {
				passes = append(passes, fmt.Sprintf("dependent "+issueLink+" targets the %q version, which is one of the valid target versions: %s", depBug.key, jiraEndpoint, depBug.key, *depBug.targetVersion, strings.Join(*options.DependentBugTargetVersions, ", ")))
			} else {
				valid = false
				fails = append(fails, fmt.Sprintf("expected dependent "+issueLink+" to target a version in %s, but it targets %q instead", depBug.key, jiraEndpoint, depBug.key, strings.Join(*options.DependentBugTargetVersions, ", "), *depBug.targetVersion))
			}
		}
	}

	if len(dependents) == 0 {
		switch {
		case options.DependentBugStates != nil && options.DependentBugTargetVersions != nil:
			valid = false
			expected := strings.Join(prettyStates(*options.DependentBugStates), ", ")
			fails = append(fails, fmt.Sprintf("expected "+issueLink+" to depend on a bug targeting a version in %s and in one of the following states: %s, but no dependents were found", bug.Key, jiraEndpoint, bug.Key, strings.Join(*options.DependentBugTargetVersions, ", "), expected))
		case options.DependentBugStates != nil:
			valid = false
			expected := strings.Join(prettyStates(*options.DependentBugStates), ", ")
			fails = append(fails, fmt.Sprintf("expected "+issueLink+" to depend on a bug in one of the following states: %s, but no dependents were found", bug.Key, jiraEndpoint, bug.Key, expected))
		case options.DependentBugTargetVersions != nil:
			valid = false
			fails = append(fails, fmt.Sprintf("expected "+issueLink+" to depend on a bug targeting a version in %s, but no dependents were found", bug.Key, jiraEndpoint, bug.Key, strings.Join(*options.DependentBugTargetVersions, ", ")))
		default:
		}
	} else {
		passes = append(passes, "bug has dependents")
	}

	// make sure all dependents are part of the parent bug's project
	for _, dependent := range dependents {
		if bug.Fields != nil {
			if !strings.HasPrefix(dependent.key, bug.Fields.Project.Key+"-") {
				valid = false
				fails = append(fails, fmt.Sprintf("dependent bug %s is not in the required `%s` project", dependent.key, bug.Fields.Project.Key))
			}
		} else {
			// this should never happen
			fails = append(fails, fmt.Sprintf("unable to identify project for issue %s", dependent.key))
		}
	}

	return valid, passes, fails
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
	if issue.Fields.Project.Key != "DFBUGS" && len(pieces) >= 2 {
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

func handleMerge(e event, gc githubClient, jc jiraclient.Client, options JiraBranchOptions, log *logrus.Entry, allRepos sets.Set[string]) error {
	if options.StateAfterMerge == nil {
		return nil
	}
	if e.missing {
		return nil
	}
	comment := e.comment(gc)

	msg := ""
	for _, refIssue := range e.issues {
		if !refIssue.IsBug {
			continue
		}
		if msg != "" {
			msg += "\n\n"
		}
		bug, err := getJira(jc, refIssue.Key(), log, comment)
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
				msg += fmt.Sprintf(issueLink+" is in an unrecognized state (%s) and will not be moved to the %s state.", refIssue.Key(), jc.JiraURL(), refIssue.Key(), bug.Fields.Status.Name, options.StateAfterMerge)
				continue
			}
		}

		links, err := jc.GetRemoteLinks(bug.ID)
		if err != nil {
			log.WithError(err).Warn("Unexpected error listing external tracker bugs for Jira bug.")
			msg += formatError("searching for external tracker bugs", jc.JiraURL(), refIssue.Key(), err)
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
			if len(parts) != 4 && (len(parts) != 5 || parts[4] != "" && parts[4] != "files") && (len(parts) != 6 || ((parts[4] != "files" || parts[5] != "") && parts[4] != "commits")) {
				log.WithError(err).Warn("Unexpected error splitting github URL for Jira external link.")
				msg += formatError(fmt.Sprintf("invalid pull identifier with %d parts: %q", len(parts), identifier), jc.JiraURL(), refIssue.Key(), err)
				continue
			}
			number, err := strconv.Atoi(parts[3])
			if err != nil {
				log.WithError(err).Warn("Unexpected error splitting github URL for Jira external link.")
				msg += formatError(fmt.Sprintf("invalid pull identifier: could not parse %s as number", parts[3]), jc.JiraURL(), refIssue.Key(), err)
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
					msg += formatError(fmt.Sprintf("checking the state of a related pull request at https://github.com/%s/%s/pull/%d", item.Org, item.Repo, item.Num), jc.JiraURL(), refIssue.Key(), err)
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
			return fmt.Sprintf(issueLink+" has %sbeen moved to the %s state.", refIssue.Key(), jc.JiraURL(), refIssue.Key(), action, options.StateAfterMerge)
		}

		if shouldMigrate {
			var commentVerified, premergeVerified bool
			if labels, err := gc.GetIssueLabels(e.org, e.repo, e.number); err != nil {
				log.WithError(err).Warn("Could not list labels on PR")
			} else {
				premergeVerified = isPreMergeVerified(bug, labels)
				commentVerified = isCommentVerified(labels)
			}
			if commentVerified {
				outcomeMessage = func(action string) string {
					return fmt.Sprintf(issueLink+" has %sbeen moved to the `VERIFIED` state.", refIssue.Key(), jc.JiraURL(), refIssue.Key(), action)
				}
				if bug.Fields.Status == nil || !strings.EqualFold("VERIFIED", bug.Fields.Status.Name) {
					if err := jc.UpdateStatus(bug.Key, "VERIFIED"); err != nil {
						log.WithError(err).Warn("Unexpected error updating jira issue.")
						msg += formatError(fmt.Sprintf("updating to the %s state", options.PreMergeStateAfterClose.Status), jc.JiraURL(), refIssue.Key(), err) + "\n\n"
						continue
					}
				}
			} else if premergeVerified {
				outcomeMessage = func(action string) string {
					return fmt.Sprintf(issueLink+" has %sbeen moved to the %s state.", refIssue.Key(), jc.JiraURL(), refIssue.Key(), action, options.PreMergeStateAfterMerge)
				}
				if options.PreMergeStateAfterMerge != nil {
					if options.PreMergeStateAfterMerge.Status != "" && (bug.Fields.Status == nil || !strings.EqualFold(bug.Fields.Status.Name, options.PreMergeStateAfterMerge.Status)) {
						if err := jc.UpdateStatus(bug.Key, options.PreMergeStateAfterMerge.Status); err != nil {
							log.WithError(err).Warn("Unexpected error updating jira bug.")
							msg += formatError(fmt.Sprintf("updating to the %s state", options.PreMergeStateAfterMerge.Status), jc.JiraURL(), refIssue.Key(), err)
							continue
						}
					}
					if options.PreMergeStateAfterMerge.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(bug.Fields.Status.Name, options.PreMergeStateAfterMerge.Resolution)) {
						updatebug := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.PreMergeStateAfterMerge.Resolution}}}
						if _, err := jc.UpdateIssue(&updatebug); err != nil {
							log.WithError(err).Warn("Unexpected error updating jira bug.")
							msg += formatError(fmt.Sprintf("updating to the %s resolution", options.PreMergeStateAfterMerge.Resolution), jc.JiraURL(), refIssue.Key(), err)
							continue
						}
					}
				}
			} else {
				if options.StateAfterMerge != nil {
					if options.StateAfterMerge.Status != "" && (bug.Fields.Status == nil || !strings.EqualFold(options.StateAfterMerge.Status, bug.Fields.Status.Name)) {
						if err := jc.UpdateStatus(refIssue.Key(), options.StateAfterMerge.Status); err != nil {
							log.WithError(err).Warn("Unexpected error updating jira issue.")
							msg += formatError(fmt.Sprintf("updating to the %s state", options.StateAfterMerge.Status), jc.JiraURL(), refIssue.Key(), err)
							continue
						}
						if options.StateAfterMerge.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(options.StateAfterMerge.Resolution, bug.Fields.Resolution.Name)) {
							updateIssue := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.StateAfterMerge.Resolution}}}
							if _, err := jc.UpdateIssue(&updateIssue); err != nil {
								log.WithError(err).Warn("Unexpected error updating jira issue.")
								msg += formatError(fmt.Sprintf("updating to the %s resolution", options.StateAfterMerge.Resolution), jc.JiraURL(), refIssue.Key(), err)
								continue
							}
						}
					}
				}
			}
			msg += fmt.Sprintf(issueLink+": %s%s", refIssue.Key(), jc.JiraURL(), refIssue.Key(), mergedMessage("All"), outcomeMessage(""))
			continue
		}
		msg += fmt.Sprintf(issueLink+": %s%s%s", refIssue.Key(), jc.JiraURL(), refIssue.Key(), mergedMessage("Some"), unmergedMessage, outcomeMessage("not "))
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
	var issues []referencedIssue
	if e.cherrypickCmd {
		issues = e.issues
	} else {
		// get the info for the PR being cherrypicked from
		pr, err := gc.GetPullRequest(e.org, e.repo, e.cherrypickFromPRNum)
		if err != nil {
			log.WithError(err).Warn("Unexpected error getting title of pull request being cherrypicked from.")
			return comment(fmt.Sprintf("Error creating a cherry-pick bug in Jira: failed to check the state of cherrypicked pull request at https://github.com/%s/%s/pull/%d: %v.\nPlease contact an administrator to resolve this issue, then request a bug refresh with <code>/jira refresh</code>.", e.org, e.repo, e.cherrypickFromPRNum, err))
		}
		// Attempt to identify bug from PR title
		issues, _, _ = jiraKeyFromTitle(pr.Title)
		if len(issues) == 0 {
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
	var bugs []referencedIssue
	var other []referencedIssue
	for i := range issues {
		if issues[i].IsBug {
			bugs = append(bugs, issues[i])
		} else {
			other = append(other, issues[i])
		}
	}
	if len(other) != 0 {
		var titles []string
		for _, issue := range other {
			titles = append(titles, issue.Key())
		}
		msg += fmt.Sprintf("Ignoring requests to cherry-pick non-bug issues: %v\n ", strings.Join(titles, ", "))
	}

	retitleList := make(map[string]string)
	for _, refIssue := range bugs {
		bug, err := getJira(jc, refIssue.Key(), log, commentWithPrefix)
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
		cloneKey, response, err := createCherryPickBug(jc, bug, e.baseRef, options, log)
		retitleList[refIssue.Key()] = cloneKey
		msg += response
		if err != nil {
			msg += err.Error()
		}
		msg += "\n\n"
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

// createCherrypickBug has the following return values:
// 1. string: key of clone
// 2. string: message to print after clone. The `handleBackport` function does not use this field.
// 3. error: a message regarding what went wrong during the clone
func createCherryPickBug(jc jiraclient.Client, bug *jira.Issue, branch string, options JiraBranchOptions, log *logrus.Entry) (string, string, error) {
	allowed, err := isBugAllowed(bug, options.AllowedSecurityLevels)
	if err != nil {
		return "", "", fmt.Errorf("failed to check is issue is in allowed security level: %w", err)
	}
	if !allowed {
		// ignore bugs that are in non-allowed groups for this repo
		return "", "", nil
	}
	oldLink := fmt.Sprintf(issueLink, bug.Key, jc.JiraURL(), bug.Key)
	for _, label := range bug.Fields.Labels {
		match := existingBackportMatch.FindString(label)
		if len(match) > 0 {
			match = strings.TrimPrefix(match, "jlp-")
			branchKey := strings.Split(match, ":")
			if branchKey[0] == branch {
				return branchKey[1], fmt.Sprintf("Detected clone of %s with correct target version. Will retitle the PR to link to the clone.", oldLink), nil
			}
		}
	}
	if options.TargetVersion == nil {
		// this should never happen if the config is properly set up
		msg := fmt.Sprintf("Could not make automatic cherrypick of %s for this PR as the target version is not set for this branch in the jira plugin config. Running refresh:\n/jira refresh", oldLink) + "\n\n"
		return "", msg, nil
	}
	targetVersion := *options.TargetVersion
	clones := identifyClones(bug)
	for _, baseClone := range clones {
		// get full issue struct
		clone, err := jc.GetIssue(baseClone.Key)
		if err != nil {
			return "", "", fmt.Errorf("failed to get %s, which is a clone of %s: %w", baseClone.Key, bug.Key, err)
		}
		cloneVersion, err := helpers.GetIssueTargetVersion(clone)
		if err != nil {
			return "", "", errors.New(formatError(fmt.Sprintf("getting the target version for clone %s", clone.Key), jc.JiraURL(), bug.Key, err))
		}
		if len(cloneVersion) == 1 && cloneVersion[0].Name == targetVersion {
			return clone.Key, fmt.Sprintf("Detected clone of %s with correct target version. Will retitle the PR to link to the clone.", oldLink), nil
		}
	}
	// clone the bug in order to not lose fields during backports, which reuse *bug
	bugCopy := *bug
	copyFields := *bug.Fields
	bugCopy.Fields = &copyFields
	// TODO: these fields can cause the clone to fail if not manually removed. It may be better to
	// perform some recursion when cloning issues, as these only error when everything else is correct...
	delete(bugCopy.Fields.Unknowns, "environment")
	delete(bugCopy.Fields.Unknowns, "customfield_12318341")
	// This is the sprint field; sprints are handled by a custom plugin, and the data given to us via
	// GetIssue is invalid for setting the field ourselves
	sprintField := bugCopy.Fields.Unknowns[helpers.SprintField]
	delete(bugCopy.Fields.Unknowns, helpers.SprintField)
	releaseNoteType := bugCopy.Fields.Unknowns[helpers.ReleaseNoteTypeField]
	releaseNoteText := bugCopy.Fields.Unknowns[helpers.ReleaseNoteTextField]
	if len(options.IgnoreCloneLabels) != 0 {
		labelsSet := sets.New[string](bugCopy.Fields.Labels...)
		labelsSet.Delete(options.IgnoreCloneLabels...)
		bugCopy.Fields.Labels = labelsSet.UnsortedList()
	}
	// unset assignee so we can more easily check when jira's internal auto-assign completes
	bugCopy.Fields.Assignee = nil
	clone, err := jc.CloneIssue(&bugCopy)
	if err != nil {
		log.WithError(err).Debugf("Failed to clone bug %+v", bug)
		return "", "", errors.New(formatError("cloning bug for cherrypick", jc.JiraURL(), bug.Key, err))
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
		return "", "", errors.New(formatError(fmt.Sprintf("updating cherry-pick bug in Jira: Created cherrypick %s, but encountered error creating `Blocks` type link with original bug", cloneLink), jc.JiraURL(), clone.Key, err))
	}
	response := fmt.Sprintf("%s has been cloned as %s. Will retitle bug to link to clone.", oldLink, cloneLink)
	// jira has automation to set the assignee to a default based on component; we wait up to 1 minute to avoid a race
	for range 10 {
		if issue, err := jc.GetIssue(clone.Key); err == nil && issue.Fields.Assignee != nil && issue.Fields.Assignee.Name != "" {
			break
		}
		time.Sleep(time.Second * 6)
	}
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
	if releaseNoteText != nil {
		update.Fields.Unknowns[helpers.ReleaseNoteTextField] = releaseNoteText
	}
	if releaseNoteType != nil {
		update.Fields.Unknowns[helpers.ReleaseNoteTypeField] = releaseNoteType
	}
	sprintID, err := helpers.GetActiveSprintID(sprintField)
	errs := []string{}
	if err != nil {
		errs = append(errs, fmt.Sprintf(`

WARNING: Failed to update the sprint for the clone. Please update the sprint manually. Full error below:
<details><summary>Full error message.</summary>

<code>
%v
</code>

</details>`, err))
	} else if sprintID != -1 {
		update.Fields.Unknowns[helpers.SprintField] = sprintID
	}
	_, err = jc.UpdateIssue(&update)
	if err != nil {
		errs = append(errs, fmt.Sprintf(`

WARNING: Failed to update the target version, assignee, and sprint for the clone. Please update these fields manually. Full error below:
<details><summary>Full error message.</summary>

<code>
%v
</code>

</details>`, err))
	}
	var errMsg error
	if len(errs) != 0 {
		errMsg = errors.New(strings.Join(errs, ""))
	}
	return clone.Key, response, errMsg
}

func handleBackport(e event, gc githubClient, jc jiraclient.Client, repoOptions map[string]JiraBranchOptions, log *logrus.Entry) error {
	comment := e.comment(gc)
	versionToBranch := map[string][]string{}
	for branch, bOpts := range repoOptions {
		if bOpts.TargetVersion != nil {
			versionToBranch[*bOpts.TargetVersion] = append(versionToBranch[*bOpts.TargetVersion], branch)
		}
	}
	missingDependencies := sets.New[string]()
	childBranches := make(map[string][]string)
	var cherrypickBranches string
	// sort for deterministic tests
	existingBranches := append(e.backportBranches, e.baseRef)
	sort.Strings(existingBranches)
	existingBranchesSet := sets.New(existingBranches...)
	for _, branch := range e.backportBranches {
		cherrypickBranches += fmt.Sprintf("\n/cherrypick %s", branch)
		if _, ok := repoOptions[branch]; !ok {
			continue
		}
		if repoOptions[branch].DependentBugTargetVersions == nil {
			continue
		}
		existingBranchesForTargetVersions := [][]string{}
		for _, dependent := range *repoOptions[branch].DependentBugTargetVersions {
			if dependentBranches, ok := versionToBranch[dependent]; ok {
				existingBranchesForTargetVersions = append(existingBranchesForTargetVersions, dependentBranches)
			}
		}
		if len(existingBranchesForTargetVersions) == 0 {
			missingDependencies.Insert(fmt.Sprintf("branch with one of the following target versions: %v", *repoOptions[branch].DependentBugTargetVersions))
		}
		for _, dependentBranches := range existingBranchesForTargetVersions {
			var branchExists bool
			if slices.ContainsFunc(dependentBranches, existingBranchesSet.Has) {
				branchExists = true
			}
			if !branchExists {
				message := dependentBranches[0]
				if len(dependentBranches) > 0 {
					for _, dependentBranch := range dependentBranches[1:] {
						message += " OR " + dependentBranch
					}
				}
				missingDependencies.Insert(message + ", ")
			} else {
				for _, dependentBranch := range dependentBranches {
					childBranches[dependentBranch] = append(childBranches[dependentBranch], branch)
				}
			}
		}
	}
	if len(missingDependencies) != 0 {
		message := "Missing required branches for backport chain:\n"
		errorMsgs := missingDependencies.UnsortedList()
		sort.Strings(errorMsgs)
		for _, errorMsg := range errorMsgs {
			message += "- " + errorMsg + "\n"
		}
		return comment(message)
	}
	createdIssuesMessageLines := []string{}
	for _, refIssue := range e.issues {
		if !refIssue.IsBug {
			continue
		}
		issue, err := jc.GetIssue(refIssue.Key())
		if err != nil {
			return comment(fmt.Sprintf("Failed to get issue %s: %v", refIssue.Key(), err))
		}
		issueBranchLogger := log.WithField("issue_branch", fmt.Sprintf("%s_%s", issue.Key, e.baseRef))
		issueBranchLogger.Infof("Child Branches map: %+v", childBranches)
		createdIssues, err := createLinkedJiras(jc, issue, e.baseRef, childBranches, repoOptions, issueBranchLogger)
		if err != nil {
			return comment(fmt.Sprintf("Failed to create backported issues: %v", err))
		}
		updateIssue := jira.Issue{Key: issue.Key, Fields: &jira.IssueFields{
			Labels: issue.Fields.Labels,
		}}
		var newLabels []string
		for key, branch := range createdIssues {
			newLabels = append(newLabels, fmt.Sprintf("jlp-%s:%s", branch, key))
			createdIssuesMessageLines = append(createdIssuesMessageLines, insertLinksIntoLine(fmt.Sprintf("- %s for branch %s", key, branch), []string{key}, jc.JiraURL()))
		}
		// sorting the labels isn't necessary for production but helps with tests
		sort.Strings(newLabels)
		updateIssue.Fields.Labels = append(updateIssue.Fields.Labels, newLabels...)
		issue, err = jc.UpdateIssue(&updateIssue)
		if err != nil {
			return comment(fmt.Sprintf("Failed to add label to issue %s: %v", issue.Key, err))
		}
	}
	// make message deterministic for tests
	sort.Strings(createdIssuesMessageLines)
	createdIssuesMessage := strings.Join(createdIssuesMessageLines, "\n")
	return comment(fmt.Sprintf("The following backport issues have been created:\n%s\n\nQueuing cherrypicks to the requested branches to be created after this PR merges:%s", createdIssuesMessage, cherrypickBranches))
}

// createLinkedJiras recursively creates all descendants of the provided parent issue based on the child branches map
// 1. map[string]string: issue key -> branch
// 2. error
func createLinkedJiras(jc jiraclient.Client, parentIssue *jira.Issue, parentBranch string, childBranches map[string][]string, repoOptions map[string]JiraBranchOptions, log *logrus.Entry) (map[string]string, error) {
	log.Infof("Starting createLinkedJiras")
	if len(childBranches[parentBranch]) == 0 {
		return nil, nil
	}
	createdIssues := make(map[string]string) // issue key -> branch
	children := []*jira.Issue{}
	log.Infof("Starting childBranch loop")
	for _, childBranch := range childBranches[parentBranch] {
		cloneKey, _, err := createCherryPickBug(jc, parentIssue, childBranch, repoOptions[childBranch], log)
		if err != nil {
			return nil, err
		}
		log.Infof("Cloned %s as %s", parentIssue.Key, cloneKey)
		createdIssues[cloneKey] = childBranch
		child, err := jc.GetIssue(cloneKey)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	for _, child := range children {
		log.Infof("creating links for child %s", child.Key)
		childIssues, err := createLinkedJiras(jc, child, createdIssues[child.Key], childBranches, repoOptions, log)
		if err != nil {
			return nil, err
		}
		maps.Copy(createdIssues, childIssues)
	}
	log.Infof("Created issues: %+v", createdIssues)
	return createdIssues, nil
}

// return values:
// 1: issues as an array of referencedIssue, if exists
// 2: missing: true/false based on whether the title is missing a jira ref
// 3: noJira: true/false based on whether the title contains jira excluding term (i.e. "NO-JIRA" or "NO-ISSUE")
func jiraKeyFromTitle(title string) ([]referencedIssue, bool, bool) {
	titleMatches := titleMatchJiraIssue.FindStringSubmatch(title)
	if len(titleMatches) == 0 || len(titleMatches) < 3 {
		return nil, true, false
	}
	if strings.EqualFold(titleMatches[2], "NO-ISSUE") || strings.EqualFold(titleMatches[2], "NO-JIRA") {
		return nil, false, true
	}

	return referencedIssues(titleMatches[0]), false, false
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
	for _, refIssue := range e.issues {
		if !refIssue.IsBug {
			return nil
		}
		if options.AddExternalLink != nil && *options.AddExternalLink {
			response := fmt.Sprintf(`This pull request references `+issueLink+`. The bug has been updated to no longer refer to the pull request using the external bug tracker.`, refIssue.Key(), jc.JiraURL(), refIssue.Key())
			changed, err := jc.DeleteRemoteLinkViaURL(refIssue.Key(), prURLFromCommentURL(e.htmlUrl))
			if err != nil && !strings.HasPrefix(err.Error(), "could not find remote link on issue with URL") {
				log.WithError(err).Warn("Unexpected error removing external tracker bug from Jira bug.")
				msg += formatError("removing this pull request from the external tracker bugs", jc.JiraURL(), refIssue.Key(), err) + "\n\n"
				continue
			}
			if options.StateAfterClose != nil || options.PreMergeStateAfterClose != nil {
				issue, err := jc.GetIssue(refIssue.Key())
				if err != nil {
					log.WithError(err).Warn("Unexpected error getting Jira issue.")
					msg += formatError("getting issue", jc.JiraURL(), refIssue.Key(), err) + "\n\n"
					continue
				}
				if !strings.EqualFold(issue.Fields.Status.Name, status.Closed) {
					links, err := jc.GetRemoteLinks(issue.ID)
					if err != nil {
						log.WithError(err).Warn("Unexpected error getting remote links for Jira issue.")
						msg += formatError("getting remote links", jc.JiraURL(), refIssue.Key(), err) + "\n\n"
						continue
					}
					if len(links) == 0 {
						bug, err := getJira(jc, refIssue.Key(), log, comment)
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
									msg += formatError(fmt.Sprintf("updating to the %s state", options.PreMergeStateAfterClose.Status), jc.JiraURL(), refIssue.Key(), err) + "\n\n"
									continue
								}
								if options.PreMergeStateAfterClose.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(options.PreMergeStateAfterClose.Resolution, bug.Fields.Resolution.Name)) {
									updateIssue := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.PreMergeStateAfterClose.Resolution}}}
									if _, err := jc.UpdateIssue(&updateIssue); err != nil {
										log.WithError(err).Warn("Unexpected error updating jira issue.")
										msg += formatError(fmt.Sprintf("updating to the %s resolution", options.PreMergeStateAfterClose.Resolution), jc.JiraURL(), refIssue.Key(), err) + "\n\n"
										continue
									}
								}
							}
						} else {
							updatedState = JiraBugState{Status: options.StateAfterClose.Status, Resolution: options.StateAfterClose.Resolution}
							if options.StateAfterClose.Status != "" && (bug.Fields.Status == nil || !strings.EqualFold(options.StateAfterClose.Status, bug.Fields.Status.Name)) {
								if err := jc.UpdateStatus(issue.ID, options.StateAfterClose.Status); err != nil {
									log.WithError(err).Warn("Unexpected error updating jira issue.")
									msg += formatError(fmt.Sprintf("updating to the %s state", options.StateAfterClose.Status), jc.JiraURL(), refIssue.Key(), err) + "\n\n"
									continue
								}
								if options.StateAfterClose.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(options.StateAfterClose.Resolution, bug.Fields.Resolution.Name)) {
									updateIssue := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.StateAfterClose.Resolution}}}
									if _, err := jc.UpdateIssue(&updateIssue); err != nil {
										log.WithError(err).Warn("Unexpected error updating jira issue.")
										msg += formatError(fmt.Sprintf("updating to the %s resolution", options.StateAfterClose.Resolution), jc.JiraURL(), refIssue.Key(), err) + "\n\n"
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

func handleVerification(e event, ghc githubClient, inserter BigQueryInserter, log *logrus.Entry) error {
	comment := e.comment(ghc)
	if len(e.verifyLater) > 0 && len(e.verify) > 0 && e.verifiedRemove {
		return comment("The `/verified`, `/verified later`, and `/verified remove` commands cannot be used in the same comment.")
	}
	msg := ""
	prLabels, err := ghc.GetIssueLabels(e.org, e.repo, e.number)
	if err != nil {
		log.WithError(err).Warn("Could not list labels on PR")
		return comment("Failed to check labels for this PR. Please try again.")
	}
	if len(e.verifyLater) > 0 {
		// make sure the PR is not already marked as verified
		var existingLabel bool
		for _, label := range prLabels {
			if label.Name == labels.Verified {
				return comment("PR is already has `verified` label. Cannot change PR to `verify-later`")
			}
			if label.Name == labels.VerifiedLater {
				existingLabel = true
			}
		}
		// only usernames can be verified-later
		for _, reason := range e.verifyLater {
			if !strings.HasPrefix(reason, "@") {
				return comment("Only users can be targets for the `/verified later` command.")
			}
		}
		if !existingLabel {
			if err := ghc.AddLabel(e.org, e.repo, e.number, labels.VerifiedLater); err != nil {
				log.WithError(err).Error("Failed to add verified later label.")
				return comment("Failed to add `verified-later` label. Please try again.")
			}
			msg = fmt.Sprintf("This PR has been marked to be verified later by `%s`. Jira issue(s) in the title of this PR will not be moved to the `VERIFIED` state on merge.", strings.Join(e.verifyLater, ","))
		} else {
			msg = fmt.Sprintf("`%s` has been added as a verify later reason for this PR. Jira issue(s) in the title of this PR will not be moved to the `VERIFIED` state on merge.", strings.Join(e.verifyLater, ","))
		}
		if inserter != nil {
			for _, reason := range e.verifyLater {
				info := VerificationInfo{
					User:      e.login,
					Reason:    reason,
					Type:      verifyLaterType,
					Org:       e.org,
					Repo:      e.repo,
					PRNum:     e.number,
					Branch:    e.baseRef,
					Timestamp: time.Now(),
				}
				if err := inserter.Put(context.TODO(), info); err != nil {
					log.WithError(err).Error("Failed to upload info to Big Query")
					// TODO: consider adding comment to PR with warning; maybe don't mark as verified and ask the user to try again?
				}
			}
		}
	}
	if len(e.verify) > 0 {
		var existingLabel bool
		for _, label := range prLabels {
			if label.Name == labels.Verified {
				existingLabel = true
				break
			}
		}
		if !existingLabel {
			if err := ghc.AddLabel(e.org, e.repo, e.number, labels.Verified); err != nil {
				log.WithError(err).Error("Failed to add verified label.")
				return comment("Failed to add `verified` label. Please try again.")
			}
			msg = fmt.Sprintf("This PR has been marked as verified by `%s`. Jira issue(s) in the title of this PR will be moved to the `VERIFIED` state on merge.", strings.Join(e.verify, ","))
		} else {
			msg = fmt.Sprintf("`%s` has been added as a verification reason for this PR. Jira issue(s) in the title of this PR will be moved to the `VERIFIED` state on merge.", strings.Join(e.verify, ","))
		}
		if inserter != nil {
			for _, reason := range e.verify {
				info := VerificationInfo{
					User:      e.login,
					Reason:    reason,
					Type:      verifyMergeType,
					Org:       e.org,
					Repo:      e.repo,
					PRNum:     e.number,
					Branch:    e.baseRef,
					Timestamp: time.Now(),
				}
				if err := inserter.Put(context.TODO(), info); err != nil {
					log.WithError(err).Error("Failed to upload info to Big Query")
					// TODO: consider adding comment to PR with warning; maybe don't mark as verified and ask the user to try again?
				}
			}
		}
	}
	if e.verifiedRemove {
		var verifyLabel, laterLabel bool
		for _, label := range prLabels {
			if label.Name == labels.Verified {
				verifyLabel = true
			} else if label.Name == labels.VerifiedLater {
				laterLabel = true
			}
		}
		if verifyLabel {
			if err := ghc.RemoveLabel(e.org, e.repo, e.number, labels.Verified); err != nil {
				log.WithError(err).Error("Failed to remove verified label.")
				return comment("Failed to remove `verified` label. Please try again.")
			}
			info := VerificationInfo{
				User:      e.login,
				Reason:    "comment",
				Type:      verifyRemoveType,
				Org:       e.org,
				Repo:      e.repo,
				PRNum:     e.number,
				Branch:    e.baseRef,
				Timestamp: time.Now(),
			}
			if err := inserter.Put(context.TODO(), info); err != nil {
				log.WithError(err).Error("Failed to upload info to Big Query")
			}
			msg += "The `verified` label has been removed."
		}
		if laterLabel {
			if err := ghc.RemoveLabel(e.org, e.repo, e.number, labels.VerifiedLater); err != nil {
				log.WithError(err).Error("Failed to remove verified-later label.")
				return comment("Failed to remove `verified-later` label. Please try again.")
			}
			info := VerificationInfo{
				User:      e.login,
				Reason:    "comment",
				Type:      verifyRemoveLaterType,
				Org:       e.org,
				Repo:      e.repo,
				PRNum:     e.number,
				Branch:    e.baseRef,
				Timestamp: time.Now(),
			}
			if err := inserter.Put(context.TODO(), info); err != nil {
				log.WithError(err).Error("Failed to upload info to Big Query")
			}
			msg += "The `verified-later` label has been removed."
		}
	}
	if len(msg) != 0 {
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
	found := slices.Contains(allowedSecurityLevel, level.Name)
	// This is a special case, for RedHat, to handle the case where a Jira issue has been marked "Restricted"
	// to allow for contributors from "other" locations the ability to cherrypick, etc.
	if !found && level.Name == "Restricted" {
		return checkRHRestrictedIssue(issue, allowedSecurityLevel)
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

// checkRHRestrictedIssue verifies that the "Red Hat Employee" is both:
//  1. an allowed security level
//  2. a member of the Contributors group
//
// If both of these conditions are true, then allow further processing of the issue.
// If not, do not process the issue any further.
func checkRHRestrictedIssue(issue *jira.Issue, allowedSecurityLevel []string) (bool, error) {
	isRHEmployeeAllowed := slices.Contains(allowedSecurityLevel, "Red Hat Employee")
	if isRHEmployeeAllowed {
		if issue == nil {
			return false, fmt.Errorf("jira issue is nil")
		}
		contributors, err := helpers.GetIssueContributors(issue)
		if err != nil {
			return false, err
		}
		isContributor := false
		for _, contributor := range *contributors {
			if contributor.Name == "Red Hat Employee" {
				isContributor = true
				break
			}
		}
		return isContributor, nil
	}
	return false, nil
}
