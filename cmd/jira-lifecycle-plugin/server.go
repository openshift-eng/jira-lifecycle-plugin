package main

import (
	"context"
	"encoding/json"
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
	"k8s.io/test-infra/prow/bugzilla"
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
	bugLink               = `[Jira Issue %s](%s/browse/%s)`
	bzLink                = `[Bugzilla bug %d](%s/show_bug.cgi?id=%d)`
	criticalSeverity      = "Critical"
	importantSeverity     = "Important"
	moderateSeverity      = "Moderate"
	lowSeverity           = "Low"
	informationalSeverity = "Informational"
)

var (
	titleMatch           = regexp.MustCompile(`(?i)OCPBUGS-([0-9]+):`)
	bzTitleMatch         = regexp.MustCompile(`(?i)Bug\s+([0-9]+):`)
	refreshCommandMatch  = regexp.MustCompile(`(?mi)^/jira refresh\s*$`)
	qaReviewCommandMatch = regexp.MustCompile(`(?mi)^/jira cc-qa\s*$`)
	cherrypickPRMatch    = regexp.MustCompile(`This is an automated cherry-pick of #([0-9]+)`)
)

type dependent struct {
	isBZ             bool
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
	bc              bugzilla.Client
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
				conditions = append(conditions, fmt.Sprintf("target the %q version", *opts[branch].TargetVersion))
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
	return pluginHelp, nil
}

type githubClient interface {
	EditComment(org, repo string, id int, comment string) error
	GetIssue(org, repo string, number int) (*github.Issue, error)
	EditIssue(org, repo string, number int, issue *github.Issue) (*github.Issue, error)
	GetPullRequest(org, repo string, number int) (*github.PullRequest, error)
	CreateComment(owner, repo string, number int, comment string) error
	GetIssueLabels(org, repo string, number int) ([]github.Label, error)
	AddLabel(owner, repo string, number int, label string) error
	RemoveLabel(owner, repo string, number int, label string) error
	WasLabelAddedByHuman(org, repo string, num int, label string) (bool, error)
	QueryWithGitHubAppsSupport(ctx context.Context, q interface{}, vars map[string]interface{}, org string) error
}

func (s *server) handleIssueComment(l *logrus.Entry, e github.IssueCommentEvent) {
	cfg := s.config()
	event, err := digestComment(s.ghc, l, e)
	if err != nil {
		l.Errorf("failed to digest comment: %v", err)
	}
	if event != nil {
		options := cfg.OptionsForBranch(event.org, event.repo, event.baseRef)
		if err := handle(s.jc, s.ghc, s.bc, options, l, *event, s.prowConfigAgent.Config().AllRepos); err != nil {
			l.Errorf("failed to handle comment: %v", err)
		}
	}
}

func bugzillaBugToDependent(bug *bugzilla.Bug) dependent {
	result := dependent{
		isBZ: true,
		key:  strconv.Itoa(bug.ID),
		bugState: JiraBugState{
			Status:     bug.Status,
			Resolution: bug.Resolution,
		},
	}
	if len(bug.TargetRelease) != 0 {
		result.targetVersion = &bug.TargetRelease[0]
	}
	if len(bug.TargetRelease) > 1 {
		result.multipleVersions = true
	}
	return result
}

func bzURLToID(url string) (int, error) {
	splitURL := strings.Split(url, "=")
	bzID := splitURL[len(splitURL)-1]
	return strconv.Atoi(bzID)
}

func handle(jc jiraclient.Client, ghc githubClient, bc bugzilla.Client, options JiraBranchOptions, log *logrus.Entry, e event, allRepos sets.String) error {
	if (e.key == "" || !strings.HasPrefix(e.key, "OCPBUGS-")) && !e.cherrypick {
		return nil
	}

	comment := e.comment(ghc)
	// check if bug is part of a restricted security level; if e.key is not set, this is a bz cherrypick, so we can ignore as the bz cherrypick function checks allowed groups for us
	if !e.missing && (e.key != "") {
		bug, err := getBug(jc, e.key, log, comment)
		if err != nil || bug == nil {
			return err
		}
		bugAllowed, err := isBugAllowed(bug, options.AllowedSecurityLevels)
		if err != nil {
			return err
		}
		if !bugAllowed {
			// ignore bugs that are in non-allowed security levels for this repo
			if e.opened || refreshCommandMatch.MatchString(e.body) {
				response := fmt.Sprintf(bugLink+" is in a security level that is not in the allowed security levels for this repo.", e.key, jc.JiraURL(), e.key)
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
	// cherrypicks follow a different pattern than normal validation
	if e.cherrypick {
		return handleCherrypick(e, ghc, jc, bc, options, log)
	}
	// merges follow a different pattern from the normal validation
	if e.merged {
		return handleMerge(e, ghc, jc, options, log, allRepos)
	}
	// close events follow a different pattern from the normal validation
	if e.closed && !e.merged {
		return handleClose(e, ghc, jc, options, log)
	}

	var needsValidLabel, needsInvalidLabel bool
	var response, severityLabel string
	if e.missing {
		log.WithField("bugMissing", true)
		log.Debug("No bug referenced.")
		needsValidLabel, needsInvalidLabel = false, false
		response = `No Jira bug is referenced in the title of this pull request.
To reference a bug, add 'OCPBUGS-XXX:' to the title of this pull request and request another bug refresh with <code>/jira refresh</code>.`
	} else {
		log = log.WithField("bugKey", e.key)

		bug, err := getBug(jc, e.key, log, comment)
		if err != nil || bug == nil {
			return err
		}

		severity, err := getSimplifiedSeverity(bug)
		if err != nil {
			return err
		}

		severityLabel = getSeverityLabel(severity)

		var dependents []dependent
		if options.DependentBugStates != nil || options.DependentBugTargetVersions != nil {
			for _, link := range bug.Fields.IssueLinks {
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
					return comment(formatError(fmt.Sprintf("searching for dependent bug %s", linkIssue.Key), jc.JiraURL(), e.key, err))
				}
				targetVersion, err := helpers.GetIssueTargetVersion(dependentIssue)
				if err != nil {
					return comment(formatError(fmt.Sprintf("failed to get target version for %s", dependentIssue.Key), jc.JiraURL(), e.key, err))
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
			if bc != nil {
				bzDependsOn, _ := helpers.GetIssueBlockedByBugzillaBug(bug)
				if bzDependsOn != nil {
					bzIDInt, err := bzURLToID(*bzDependsOn)
					if err != nil {
						return comment(formatError(fmt.Sprintf("converting bugzilla URL %s to an ID", *bzDependsOn), bc.Endpoint(), e.key, err))
					}

					bzDependent, err := getBZBug(bc, bzIDInt, log, comment)
					if err != nil {
						return err
					}
					dependents = append(dependents, bugzillaBugToDependent(bzDependent))
				}
			}
		}

		bugzillaURL := ""
		if bc != nil {
			bugzillaURL = bc.Endpoint()

			// if bug depends on a bugzilla bug, sync keywords, whiteboard, and CVE info to labels
			for _, dependent := range dependents {
				if dependent.isBZ {
					// this cannot error here, as we converted the key for bugzilla bugs from int to string above
					bzID, _ := strconv.Atoi(dependent.key)
					bzDependent, err := getBZBug(bc, bzID, log, comment)
					if err != nil {
						return err
					}
					labels, err := getBZLabels(bc, bzDependent)
					if err != nil {
						return comment(formatError("identifying labels from dependent bugzilla bug", bc.Endpoint(), e.key, err))
					}
					existingLabels := sets.NewString(bug.Fields.Labels...)
					allLabels := sets.NewString()
					changed := false
					for _, label := range labels {
						allLabels.Insert(label)
						if !existingLabels.Has(label) {
							changed = true
						}
					}
					if changed {
						updateIssue := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Labels: allLabels.List()}}
						if _, err := jc.UpdateIssue(&updateIssue); err != nil {
							log.WithError(err).Warn("Unexpected error updating jira issue.")
							return comment(formatError(fmt.Sprintf("updating list of labels to: %+v", allLabels.List()), jc.JiraURL(), e.key, err))
						}
					}
				}
			}
		}
		valid, invalidDependentProject, validationsRun, why := validateBug(bug, dependents, options, jc.JiraURL(), bugzillaURL)
		needsValidLabel, needsInvalidLabel = valid, !valid
		if valid {
			log.Debug("Valid bug found.")
			response = fmt.Sprintf(`This pull request references `+bugLink+`, which is valid.`, e.key, jc.JiraURL(), e.key)
			// if configured, move the bug to the new state
			if options.StateAfterValidation != nil {
				if options.StateAfterValidation.Status != "" && (bug.Fields.Status == nil || !strings.EqualFold(options.StateAfterValidation.Status, bug.Fields.Status.Name)) {
					if err := jc.UpdateStatus(bug.ID, options.StateAfterValidation.Status); err != nil {
						log.WithError(err).Warn("Unexpected error updating jira issue.")
						return comment(formatError(fmt.Sprintf("updating to the %s state", options.StateAfterValidation.Status), jc.JiraURL(), e.key, err))
					}
					if options.StateAfterValidation.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(options.StateAfterValidation.Resolution, bug.Fields.Resolution.Name)) {
						updateIssue := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.StateAfterValidation.Resolution}}}
						if _, err := jc.UpdateIssue(&updateIssue); err != nil {
							log.WithError(err).Warn("Unexpected error updating jira issue.")
							return comment(formatError(fmt.Sprintf("updating to the %s resolution", options.StateAfterValidation.Resolution), jc.JiraURL(), e.key, err))
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

			qaContactDetail, err := helpers.GetIssueQaContact(bug)
			if err != nil {
				return comment(formatError("processing qa contact information for the bug", jc.JiraURL(), e.key, err))
			}
			if qaContactDetail == nil {
				if e.cc {
					response += fmt.Sprintf(bugLink+" does not have a QA contact, skipping assignment", e.key, jc.JiraURL(), e.key)
				}
			} else if qaContactDetail.EmailAddress == "" {
				if e.cc {
					response += fmt.Sprintf("QA contact for "+bugLink+" does not have a listed email, skipping assignment", e.key, jc.JiraURL(), e.key)
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
					return comment(formatError(fmt.Sprintf("querying GitHub for users with public email (%s)", email), jc.JiraURL(), e.key, err))
				}
				response += fmt.Sprint("\n\n", processQuery(query, email, log))
			}
		} else {
			log.Debug("Invalid bug found.")
			var formattedReasons string
			for _, reason := range why {
				formattedReasons += fmt.Sprintf(" - %s\n", reason)
			}
			if invalidDependentProject {
				formattedReasons += `
All dependent bugs must be part of the OCPBUGS project. If you are backporting a fix that was originally tracked in Bugzilla, follow these steps to handle the backport:
1. Create a new bug in the OCPBUGS Jira project to match the original bugzilla bug. The important fields that should match are the title, description, target version, and status.
2. Use the Jira UI to clone the Jira bug, then in the clone bug:
  a. Set the target version to the release you are cherrypicking to.
  b. Add an issue link “is blocked by”, which links to the original jira bug
3. Use the cherrypick github command to create the cherrypicked PR. Once that new PR is created, retitle the PR and replace the BUG XXX: with OCPBUGS-XXX: to match the new Jira story.

Note that the mirrored bug in OCPBUGSM should not be involved in this process at all.
`
			}
			response = fmt.Sprintf(`This pull request references `+bugLink+`, which is invalid:
%s
Comment <code>/jira refresh</code> to re-evaluate validity if changes to the Jira bug are made, or edit the title of this pull request to link to a different bug.`, e.key, jc.JiraURL(), e.key, formattedReasons)
		}

		if options.AddExternalLink != nil && *options.AddExternalLink {
			changed, err := upsertGitHubLinkToIssue(log, bug.ID, jc, e)
			if err != nil {
				log.WithError(err).Warn("Unexpected error adding external tracker bug to Jira bug.")
				return comment(formatError("adding this pull request to the external tracker bugs", jc.JiraURL(), e.key, err))
			}
			if changed {
				response += "\n\nThe bug has been updated to refer to the pull request using the external bug tracker."
			}
		}

	}

	// ensure label state is correct. Do not propagate errors
	// as it is more important to report to the user than to
	// fail early on a label check.
	currentLabels, err := ghc.GetIssueLabels(e.org, e.repo, e.number)
	if err != nil {
		log.WithError(err).Warn("Could not list labels on PR")
	}
	var hasValidBZLabel, hasValidJiraLabel, hasInvalidLabel bool
	var severityLabelToRemove string
	for _, l := range currentLabels {
		if l.Name == labels.ValidBug {
			hasValidJiraLabel = true
		}
		if l.Name == labels.BugzillaValidBug {
			hasValidBZLabel = true
		}
		if l.Name == labels.InvalidBug {
			hasInvalidLabel = true
		}
		if l.Name == labels.SeverityCritical ||
			l.Name == labels.SeverityImportant ||
			l.Name == labels.SeverityModerate ||
			l.Name == labels.SeverityLow ||
			l.Name == labels.SeverityInformational {
			severityLabelToRemove = l.Name
		}
	}

	if severityLabelToRemove != "" && severityLabel != severityLabelToRemove {
		if err := ghc.RemoveLabel(e.org, e.repo, e.number, severityLabelToRemove); err != nil {
			log.WithError(err).Error("Failed to remove severity bug label.")
		}
	}
	if severityLabel != "" && severityLabel != severityLabelToRemove {
		if err := ghc.AddLabel(e.org, e.repo, e.number, severityLabel); err != nil {
			log.WithError(err).Error("Failed to add severity bug label.")
		}
	}

	if hasValidJiraLabel && !needsValidLabel {
		humanLabelled, err := ghc.WasLabelAddedByHuman(e.org, e.repo, e.number, labels.ValidBug)
		if err != nil {
			// Return rather than potentially doing the wrong thing. The user can re-trigger us.
			return fmt.Errorf("failed to check if %s label was added by a human: %w", labels.ValidBug, err)
		}
		if humanLabelled {
			// This will make us remove the invalid label if it exists but saves us another check if it was
			// added by a human. It is reasonable to assume that it should be absent if the valid label was
			// manually added.
			needsInvalidLabel = false
			needsValidLabel = true
			response += fmt.Sprintf("\n\nRetaining the %s label as it was manually added.", labels.ValidBug)
		}
	}

	if hasValidBZLabel && !needsValidLabel {
		humanLabelled, err := ghc.WasLabelAddedByHuman(e.org, e.repo, e.number, labels.BugzillaValidBug)
		if err != nil {
			// Return rather than potentially doing the wrong thing. The user can re-trigger us.
			return fmt.Errorf("failed to check if %s label was added by a human: %w", labels.BugzillaValidBug, err)
		}
		if humanLabelled {
			// This will make us remove the invalid label if it exists but saves us another check if it was
			// added by a human. It is reasonable to assume that it should be absent if the valid label was
			// manually added.
			needsInvalidLabel = false
			needsValidLabel = true
			response += fmt.Sprintf("\n\nRetaining the %s label as it was manually added.", labels.BugzillaValidBug)
		}
	}

	if needsValidLabel {
		if !hasValidJiraLabel {
			if err := ghc.AddLabel(e.org, e.repo, e.number, labels.ValidBug); err != nil {
				log.WithError(err).Error("Failed to add valid bug label.")
			}
		}
		if !hasValidBZLabel {
			if err := ghc.AddLabel(e.org, e.repo, e.number, labels.BugzillaValidBug); err != nil {
				log.WithError(err).Error("Failed to add valid bugzilla bug label.")
			}
		}
	} else {
		if hasValidJiraLabel {
			if err := ghc.RemoveLabel(e.org, e.repo, e.number, labels.ValidBug); err != nil {
				log.WithError(err).Error("Failed to remove valid bug label.")
			}
		}
		if hasValidBZLabel {
			if err := ghc.RemoveLabel(e.org, e.repo, e.number, labels.BugzillaValidBug); err != nil {
				log.WithError(err).Error("Failed to remove valid bugzilla bug label.")
			}
		}
	}

	if needsInvalidLabel && !hasInvalidLabel {
		if err := ghc.AddLabel(e.org, e.repo, e.number, labels.InvalidBug); err != nil {
			log.WithError(err).Error("Failed to add invalid bug label.")
		}
	} else if !needsInvalidLabel && hasInvalidLabel {
		if err := ghc.RemoveLabel(e.org, e.repo, e.number, labels.InvalidBug); err != nil {
			log.WithError(err).Error("Failed to remove invalid bug label.")
		}
	}

	return comment(response)
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
		if err := handle(s.jc, s.ghc, s.bc, options, l, *event, s.prowConfigAgent.Config().AllRepos); err != nil {
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
		pre.Action != github.PullRequestActionClosed {
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
	e.key, e.missing = bugKeyFromTitle(title)
	// in the case that the title used to reference a bug and no longer does we
	// want to handle this to remove labels

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
	prevId, missing := bugKeyFromTitle(changes.Title.From)
	if missing {
		// title did not previously reference a bug
		return intermediate, nil
	}

	// if the referenced bug has not changed in the update, ignore it
	if prevId == e.key {
		logrus.Debugf("Referenced OCPBUGS story (%s) has not changed, not handling event.", e.key)
		return nil, nil
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
	var cc bool
	switch {
	case refreshCommandMatch.MatchString(ice.Comment.Body):
		// continue without updating bool values
	case qaReviewCommandMatch.MatchString(ice.Comment.Body):
		cc = true
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

	e := &event{org: org, repo: repo, baseRef: pr.Base.Ref, number: number, merged: pr.Merged, state: pr.State, body: ice.Comment.Body, title: ice.Issue.Title, htmlUrl: ice.Comment.HTMLURL, login: ice.Comment.User.Login, cc: cc}

	e.key, e.missing = bugKeyFromTitle(pr.Title)

	return e, nil
}

type event struct {
	org, repo, baseRef              string
	number                          int
	key                             string
	missing, merged, closed, opened bool
	state                           string
	body, title, htmlUrl, login     string
	cc                              bool
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
func validateBug(bug *jira.Issue, dependents []dependent, options JiraBranchOptions, jiraEndpoint, bzEndpoint string) (bool, bool, []string, []string) {
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
		targetVersion, err := helpers.GetIssueTargetVersion(bug)
		if err != nil {
			valid = false
			errors = append(errors, fmt.Sprintf("failed to get target version for bug: %v", err))
		} else {
			if len(targetVersion) == 0 {
				valid = false
				errors = append(errors, fmt.Sprintf("expected the bug to target the %q version, but no target version was set", *options.TargetVersion))
			} else if len(targetVersion) > 1 {
				valid = false
				errors = append(errors, fmt.Sprintf("expected the bug to target only the %q version, but multiple target versions were set", *options.TargetVersion))
			} else if *options.TargetVersion != targetVersion[0].Name {
				valid = false
				errors = append(errors, fmt.Sprintf("expected the bug to target the %q version, but it targets %q instead", *options.TargetVersion, targetVersion[0].Name))
			} else {
				validations = append(validations, fmt.Sprintf("bug target version (%s) matches configured target version for branch (%s)", targetVersion[0].Name, *options.TargetVersion))
			}
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

	if options.DependentBugStates != nil {
		for _, bug := range dependents {
			if !bug.isBZ && !strings.HasPrefix(bug.key, "OCPBUGS-") {
				continue
			}
			link := ""
			endpoint := ""
			if bug.isBZ {
				link = bzLink
				endpoint = bzEndpoint
			} else {
				link = bugLink
				endpoint = jiraEndpoint
			}
			if !bug.bugState.matches(*options.DependentBugStates) {
				valid = false
				expected := strings.Join(prettyStates(*options.DependentBugStates), ", ")
				actual := PrettyStatus(bug.bugState.Status, bug.bugState.Resolution)
				errors = append(errors, fmt.Sprintf("expected dependent "+link+" to be in one of the following states: %s, but it is %s instead", bug.key, endpoint, bug.key, expected, actual))
			} else {
				validations = append(validations, fmt.Sprintf("dependent bug "+link+" is in the state %s, which is one of the valid states (%s)", bug.key, endpoint, bug.key, PrettyStatus(bug.bugState.Status, bug.bugState.Resolution), strings.Join(prettyStates(*options.DependentBugStates), ", ")))
			}
		}
	}

	if options.DependentBugTargetVersions != nil {
		for _, bug := range dependents {
			if !bug.isBZ && !strings.HasPrefix(bug.key, "OCPBUGS-") {
				continue
			}
			link := ""
			endpoint := ""
			if bug.isBZ {
				link = bzLink
				endpoint = bzEndpoint
			} else {
				link = bugLink
				endpoint = jiraEndpoint
			}
			if bug.targetVersion == nil {
				valid = false
				errors = append(errors, fmt.Sprintf("expected dependent "+link+" to target a version in %s, but no target version was set", bug.key, endpoint, bug.key, strings.Join(*options.DependentBugTargetVersions, ", ")))
			} else if bug.multipleVersions {
				valid = false
				errors = append(errors, fmt.Sprintf("expected dependent "+link+" to target a version in %s, but it has multiple target versions", bug.key, endpoint, bug.key, strings.Join(*options.DependentBugTargetVersions, ", ")))
			} else if sets.NewString(*options.DependentBugTargetVersions...).Has(*bug.targetVersion) {
				validations = append(validations, fmt.Sprintf("dependent "+link+" targets the %q version, which is one of the valid target versions: %s", bug.key, endpoint, bug.key, *bug.targetVersion, strings.Join(*options.DependentBugTargetVersions, ", ")))
			} else {
				valid = false
				errors = append(errors, fmt.Sprintf("expected dependent "+link+" to target a version in %s, but it targets %q instead", bug.key, endpoint, bug.key, strings.Join(*options.DependentBugTargetVersions, ", "), *bug.targetVersion))
			}
		}
	}

	if len(dependents) == 0 {
		switch {
		case options.DependentBugStates != nil && options.DependentBugTargetVersions != nil:
			valid = false
			expected := strings.Join(prettyStates(*options.DependentBugStates), ", ")
			errors = append(errors, fmt.Sprintf("expected "+bugLink+" to depend on a bug targeting a version in %s and in one of the following states: %s, but no dependents were found", bug.Key, jiraEndpoint, bug.Key, strings.Join(*options.DependentBugTargetVersions, ", "), expected))
		case options.DependentBugStates != nil:
			valid = false
			expected := strings.Join(prettyStates(*options.DependentBugStates), ", ")
			errors = append(errors, fmt.Sprintf("expected "+bugLink+" to depend on a bug in one of the following states: %s, but no dependents were found", bug.Key, jiraEndpoint, bug.Key, expected))
		case options.DependentBugTargetVersions != nil:
			valid = false
			errors = append(errors, fmt.Sprintf("expected "+bugLink+" to depend on a bug targeting a version in %s, but no dependents were found", bug.Key, jiraEndpoint, bug.Key, strings.Join(*options.DependentBugTargetVersions, ", ")))
		default:
		}
	} else {
		validations = append(validations, "bug has dependents")
	}

	// make sure all dependents are part of OCPBUGS
	invalidDependentProject := false
	for _, dependent := range dependents {
		if !dependent.isBZ && !strings.HasPrefix(dependent.key, "OCPBUGS-") {
			valid = false
			errors = append(validations, fmt.Sprintf("dependent bug %s is not in the required `OCPBUGS` project", dependent.key))
			invalidDependentProject = true
		}
	}

	return valid, invalidDependentProject, validations, errors
}

type prParts struct {
	Org  string
	Repo string
	Num  int
}

func handleMerge(e event, gc githubClient, jc jiraclient.Client, options JiraBranchOptions, log *logrus.Entry, allRepos sets.String) error {
	comment := e.comment(gc)

	if options.StateAfterMerge == nil {
		return nil
	}
	if e.missing {
		return nil
	}
	bug, err := getBug(jc, e.key, log, comment)
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
			return comment(fmt.Sprintf(bugLink+" is in an unrecognized state (%s) and will not be moved to the %s state.", e.key, jc.JiraURL(), e.key, bug.Fields.Status.Name, options.StateAfterMerge))
		}
	}

	links, err := jc.GetRemoteLinks(bug.ID)
	if err != nil {
		log.WithError(err).Warn("Unexpected error listing external tracker bugs for Jira bug.")
		return comment(formatError("searching for external tracker bugs", jc.JiraURL(), e.key, err))
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
		if len(parts) != 4 && !(len(parts) == 5 && (parts[4] == "" || parts[4] == "files")) && !(len(parts) == 6 && (parts[4] == "files" && parts[5] == "")) {
			log.WithError(err).Warn("Unexpected error splitting github URL for Jira external link.")
			return comment(formatError(fmt.Sprintf("invalid pull identifier with %d parts: %q", len(parts), identifier), jc.JiraURL(), e.key, err))
		}
		number, err := strconv.Atoi(parts[3])
		if err != nil {
			log.WithError(err).Warn("Unexpected error splitting github URL for Jira external link.")
			return comment(formatError(fmt.Sprintf("invalid pull identifier: could not parse %s as number", parts[3]), jc.JiraURL(), e.key, err))
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
				return comment(formatError(fmt.Sprintf("checking the state of a related pull request at https://github.com/%s/%s/pull/%d", item.Org, item.Repo, item.Num), jc.JiraURL(), e.key, err))
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
		return fmt.Sprintf(bugLink+" has %sbeen moved to the %s state.", e.key, jc.JiraURL(), e.key, action, options.StateAfterMerge)
	}

	if shouldMigrate {
		if options.StateAfterMerge != nil {
			if options.StateAfterMerge.Status != "" && (bug.Fields.Status == nil || !strings.EqualFold(options.StateAfterMerge.Status, bug.Fields.Status.Name)) {
				if err := jc.UpdateStatus(e.key, options.StateAfterMerge.Status); err != nil {
					log.WithError(err).Warn("Unexpected error updating jira issue.")
					return comment(formatError(fmt.Sprintf("updating to the %s state", options.StateAfterMerge.Status), jc.JiraURL(), e.key, err))
				}
				if options.StateAfterMerge.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(options.StateAfterMerge.Resolution, bug.Fields.Resolution.Name)) {
					updateIssue := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.StateAfterMerge.Resolution}}}
					if _, err := jc.UpdateIssue(&updateIssue); err != nil {
						log.WithError(err).Warn("Unexpected error updating jira issue.")
						return comment(formatError(fmt.Sprintf("updating to the %s resolution", options.StateAfterMerge.Resolution), jc.JiraURL(), e.key, err))
					}
				}
			}
		}
		return comment(fmt.Sprintf("%s%s", mergedMessage("All"), outcomeMessage("")))
	}
	return comment(fmt.Sprintf("%s%s%s", mergedMessage("Some"), unmergedMessage, outcomeMessage("not ")))
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

func bzComponentsToJiraComponents(component string, subcomponents map[string][]string) ([]string, error) {
	// if no subcomponent, just process component
	if _, ok := subcomponents[component]; !ok {
		if jiraComp, ok := bzToJiraComponentMapping[component]; !ok {
			return nil, fmt.Errorf("No mapping from bz component %s to a jira component found", component)
		} else {
			return []string{jiraComp}, nil
		}
	}
	components := []string{}
	for _, sc := range subcomponents[component] {
		if jiraComp, ok := bzToJiraComponentMapping[fmt.Sprintf("%s/%s", component, sc)]; !ok {
			return nil, fmt.Errorf("No mapping from bz component %s with subcomponent %s to a jira component found", component, sc)
		} else {
			components = append(components, jiraComp)
		}
	}
	return components, nil
}

func handleBZCherrypick(e event, gc githubClient, jc jiraclient.Client, bc bugzilla.Client, parentBZID int, parentPR *github.PullRequest, options JiraBranchOptions, log *logrus.Entry) error {
	comment := e.comment(gc)
	parentBug, err := getBZBug(bc, parentBZID, log, comment)
	if err != nil {
		return err
	}
	// check if in allowed groups; as BZ handling it a temporary measure, we can hardcode allowed groups
	markAsPrivate := false
	for _, group := range parentBug.Groups {
		if (group != "redhat") && (group != "qe_staff") && (group != "nec") {
			log.Infof("Cherrypick PR https://github.com/%s/%s/pull/%d being ignored as it is in a non-allowed group", e.org, e.repo, e.number)
			return nil
		}
		if group == "redhat" {
			markAsPrivate = true
		}
	}
	// description is stored as the first comment on the bug
	comments, err := bc.GetComments(parentBZID)
	if err != nil {
		log.WithError(err).Errorf("failed to get comments for BZ ID %d", parentBZID)
		return comment(formatBZError("getting description for bugzilla bug", bc.Endpoint(), parentBZID, err))
	}
	if len(comments) == 0 {
		log.Errorf("comment list empty for bugzilla ID %d", parentBZID)
		return comment(formatBZError("getting description for bugzilla bug", bc.Endpoint(), parentBZID, err))
	}
	if options.TargetVersion == nil {
		return comment(fmt.Sprintf("Could not make automatic cherrypick of %s for this PR as the target version is not set for this branch in the jira plugin config. Running refresh:\n/jira refresh", parentPR.HTMLURL))
	}
	targetVersion := *options.TargetVersion
	var newIssue *jira.Issue
	response := ""
	oldLink := ""
	newIssue = &jira.Issue{Fields: &jira.IssueFields{
		Project: jira.Project{
			Name: "OCPBUGS",
		},
		Description: fmt.Sprintf("This bug is a backport clone of "+bzLink+". The following is the description of the original bug:\n---\n%s", parentBug.ID, bc.Endpoint(), parentBug.ID, comments[0].Text),
		Summary:     parentBug.Summary,
		Unknowns: tcontainer.MarshalMap{
			helpers.BlockedByBugzillaBug: fmt.Sprintf("%s/show_bug.cgi?id=%d", bc.Endpoint(), parentBZID),
			helpers.TargetVersionField:   []*jira.Version{{Name: targetVersion}},
		},
	}}
	if markAsPrivate {
		newIssue.Fields.Unknowns["security"] = helpers.SecurityLevel{Name: "Red Hat Employee"}
	}
	// subcomponents are not returned by default
	subcomponents, err := bc.GetSubComponentsOnBug(parentBug.ID)
	if err != nil {
		return comment(formatBZError("getting subcomponents", bc.Endpoint(), parentBZID, err))
	}
	for _, component := range parentBug.Component {
		newComponents, err := bzComponentsToJiraComponents(component, subcomponents)
		if err != nil {
			return comment(formatBZError("translating bugzilla components to jira components", bc.Endpoint(), parentBZID, err))
		}
		for _, newComp := range newComponents {
			newIssue.Fields.Components = append(newIssue.Fields.Components, &jira.Component{Name: newComp})
		}
	}
	labels, err := getBZLabels(bc, parentBug)
	if err != nil {
		return comment(formatBZError("getting `Block` bugs", bc.Endpoint(), parentBZID, err))
	}
	newIssue.Fields.Labels = labels
	newIssue, err = jc.CreateIssue(newIssue)
	if err != nil {
		log.WithError(err).Error("failed to create jira issue for bz backport")
		return comment(formatError("creating backport issue", jc.JiraURL(), e.key, err))
	}
	oldLink = fmt.Sprintf(bzLink, parentBZID, bc.Endpoint(), parentBZID)
	// Replace old bugID in title with new cloneID
	newTitle := strings.ReplaceAll(e.title, fmt.Sprintf("Bug %d", parentBZID), newIssue.Key)
	cloneLink := fmt.Sprintf(bugLink, newIssue.Key, jc.JiraURL(), newIssue.Key)
	response = fmt.Sprintf("%s%s has been cloned as %s. Retitling PR to link against new bug.\n/retitle %s", response, oldLink, cloneLink, newTitle)
	return comment(response)
}

func handleCherrypick(e event, gc githubClient, jc jiraclient.Client, bc bugzilla.Client, options JiraBranchOptions, log *logrus.Entry) error {
	comment := e.comment(gc)
	// get the info for the PR being cherrypicked from
	pr, err := gc.GetPullRequest(e.org, e.repo, e.cherrypickFromPRNum)
	if err != nil {
		log.WithError(err).Warn("Unexpected error getting title of pull request being cherrypicked from.")
		return comment(fmt.Sprintf("Error creating a cherry-pick bug in Jira: failed to check the state of cherrypicked pull request at https://github.com/%s/%s/pull/%d: %v.\nPlease contact an administrator to resolve this issue, then request a bug refresh with <code>/jira refresh</code>.", e.org, e.repo, e.cherrypickFromPRNum, err))
	}
	// Attempt to identify bug from PR title
	bugKey, bugMissing := bugKeyFromTitle(pr.Title)
	if bugMissing {
		bzID, missing, err := bzIDFromTitle(pr.Title)
		if err != nil {
			log.WithError(err).Warn("Unexpected error identifying bugzilla bug from title")
			return comment(fmt.Sprintf("Error creating a cherry-pick bug in Jira: failed to parse bugzilla ID from title of https://github.com/%s/%s/pull/%d: %v.\nPlease contact an administrator to resolve this issue, then request a bug refresh with <code>/jira refresh</code>.", e.org, e.repo, e.cherrypickFromPRNum, err))
		}
		if missing {
			log.Debugf("Parent PR %d doesn't have associated bug; not creating cherrypicked bug", pr.Number)
			// if there is no jira bug, we should simply ignore this PR
			return nil
		} else {
			log.Infof("Handling BZ Cherrypick for bug %d", bzID)
			return handleBZCherrypick(e, gc, jc, bc, bzID, pr, options, log)
		}
	}
	// Since getBug generates a comment itself, we have to add a prefix explaining that this was a cherrypick attempt to the comment
	commentWithPrefix := func(body string) error {
		return comment(fmt.Sprintf("Failed to create a cherry-pick bug in Jira: %s", body))
	}
	bug, err := getBug(jc, bugKey, log, commentWithPrefix)
	if err != nil || bug == nil {
		return err
	}
	allowed, err := isBugAllowed(bug, options.AllowedSecurityLevels)
	if err != nil {
		return fmt.Errorf("failed to check is issue is in allowed security level: %w", err)
	}
	if !allowed {
		// ignore bugs that are in non-allowed groups for this repo
		return nil
	}
	clones := identifyClones(bug)
	oldLink := fmt.Sprintf(bugLink, bugKey, jc.JiraURL(), bugKey)
	if options.TargetVersion == nil {
		return comment(fmt.Sprintf("Could not make automatic cherrypick of %s for this PR as the target version is not set for this branch in the jira plugin config. Running refresh:\n/jira refresh", oldLink))
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
			return comment(formatError(fmt.Sprintf("getting the target version for clone %s", clone.Key), jc.JiraURL(), bug.Key, err))
		}
		if len(cloneVersion) == 1 && cloneVersion[0].Name == targetVersion {
			newTitle := strings.Replace(e.title, bugKey, clone.Key, 1)
			return comment(fmt.Sprintf("Detected clone of %s with correct target version. Retitling PR to link to clone:\n/retitle %s", oldLink, newTitle))
		}
	}
	clone, err := jc.CloneIssue(bug)
	if err != nil {
		log.WithError(err).Debugf("Failed to clone bug %s", bugKey)
		return comment(formatError("cloning bug for cherrypick", jc.JiraURL(), bug.Key, err))
	}
	cloneLink := fmt.Sprintf(bugLink, clone.Key, jc.JiraURL(), clone.Key)
	// Update the version of the bug to the target release
	update := jira.Issue{
		Key: clone.Key,
		Fields: &jira.IssueFields{
			Unknowns: tcontainer.MarshalMap{
				helpers.TargetVersionField: []*jira.Version{{Name: targetVersion}},
			},
		},
	}
	_, err = jc.UpdateIssue(&update)
	if err != nil {
		log.WithError(err).Debugf("Unable to update target version and dependencies for bug %s", clone.Key)
		return comment(formatError(fmt.Sprintf("updating cherry-pick bug in Jira: Created cherrypick %s, but encountered error updating target version", cloneLink), jc.JiraURL(), clone.Key, err))
	}
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
		return comment(formatError(fmt.Sprintf("updating cherry-pick bug in Jira: Created cherrypick %s, but encountered error creating `Blocks` type link with original bug", cloneLink), jc.JiraURL(), clone.Key, err))
	}
	// Replace old bugID in title with new cloneID
	newTitle := strings.ReplaceAll(e.title, bugKey, clone.Key)
	response := fmt.Sprintf("%s has been cloned as %s. Retitling PR to link against new bug.\n/retitle %s", oldLink, cloneLink, newTitle)
	return comment(response)
}

func bugKeyFromTitle(title string) (string, bool) {
	mat := titleMatch.FindStringSubmatch(title)
	if mat == nil {
		return "", true
	}
	return strings.TrimSuffix(mat[0], ":"), false
}

func bzIDFromTitle(title string) (int, bool, error) {
	mat := bzTitleMatch.FindStringSubmatch(title)
	if mat == nil {
		return 0, true, nil
	}
	bugID, err := strconv.Atoi(mat[1])
	if err != nil {
		// should be impossible based on the regex
		return 0, false, fmt.Errorf("Failed to parse bug ID (%s) as int", mat[1])
	}
	return bugID, false, nil
}

func getBug(jc jiraclient.Client, bugKey string, log *logrus.Entry, comment func(string) error) (*jira.Issue, error) {
	bug, err := jc.GetIssue(bugKey)
	if err != nil && !jiraclient.IsNotFound(err) {
		log.WithError(err).Warn("Unexpected error searching for Jira bug.")
		return nil, comment(formatError("searching", jc.JiraURL(), bugKey, err))
	}
	if jiraclient.IsNotFound(err) || bug == nil {
		log.Debug("No bug found.")
		return nil, comment(fmt.Sprintf(`No Jira issue with key %s exists in the tracker at %s.
Once a valid bug is referenced in the title of this pull request, request a bug refresh with <code>/jira refresh</code>.`,
			bugKey, jc.JiraURL()))
	}
	return bug, nil
}

func getBZBug(bc bugzilla.Client, bugId int, log *logrus.Entry, comment func(string) error) (*bugzilla.Bug, error) {
	bug, err := bc.GetBug(bugId)
	if err != nil && !bugzilla.IsNotFound(err) {
		log.WithError(err).Warn("Unexpected error searching for Bugzilla bug.")
		return nil, comment(fmt.Sprintf("Error encountered trying to get bugzilla bug ID %d: %v", bugId, err))
	}
	if bugzilla.IsNotFound(err) || bug == nil {
		log.Debug("No bug found.")
		return nil, comment(fmt.Sprintf(`No Bugzilla bug with ID %d exists in the tracker at %s.
Once a valid bug is referenced in the title of this pull request, request a bug refresh with <code>/bugzilla refresh</code>.`,
			bugId, bc.Endpoint()))
	}
	return bug, nil
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

func formatBZError(action, endpoint string, bugID int, err error) string {
	knownErrors := map[string]string{
		"There was an error reported for a GitHub REST call": "The Bugzilla server failed to load data from GitHub when creating the bug. This is usually caused by rate-limiting, please try again later.",
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
	return fmt.Sprintf(`An error was encountered %s for bug %d on the Bugzilla server at %s. %s

<details><summary>Full error message.</summary>

<code>
%v
</code>

</details>

Please contact an administrator to resolve this issue, then request a bug refresh with <code>/jira refresh</code>.`,
		action, bugID, endpoint, digest, err)
}

var PrivateVisibility = jira.CommentVisibility{Type: "group", Value: "Red Hat Employee"}

func handleClose(e event, gc githubClient, jc jiraclient.Client, options JiraBranchOptions, log *logrus.Entry) error {
	comment := e.comment(gc)
	if e.missing {
		return nil
	}
	if options.AddExternalLink != nil && *options.AddExternalLink {
		response := fmt.Sprintf(`This pull request references `+bugLink+`. The bug has been updated to no longer refer to the pull request using the external bug tracker.`, e.key, jc.JiraURL(), e.key)
		changed, err := jc.DeleteRemoteLinkViaURL(e.key, prURLFromCommentURL(e.htmlUrl))
		if err != nil && !strings.HasPrefix(err.Error(), "could not find remote link on issue with URL") {
			log.WithError(err).Warn("Unexpected error removing external tracker bug from Jira bug.")
			return comment(formatError("removing this pull request from the external tracker bugs", jc.JiraURL(), e.key, err))
		}
		if options.StateAfterClose != nil {
			issue, err := jc.GetIssue(e.key)
			if err != nil {
				log.WithError(err).Warn("Unexpected error getting Jira issue.")
				return comment(formatError("getting issue", jc.JiraURL(), e.key, err))
			}
			if !strings.EqualFold(issue.Fields.Status.Name, status.Closed) {
				links, err := jc.GetRemoteLinks(issue.ID)
				if err != nil {
					log.WithError(err).Warn("Unexpected error getting remote links for Jira issue.")
					return comment(formatError("getting remote links", jc.JiraURL(), e.key, err))
				}
				if len(links) == 0 {
					bug, err := getBug(jc, e.key, log, comment)
					if err != nil || bug == nil {
						return err
					}
					if options.StateAfterClose.Status != "" && (bug.Fields.Status == nil || !strings.EqualFold(options.StateAfterClose.Status, bug.Fields.Status.Name)) {
						if err := jc.UpdateStatus(issue.ID, options.StateAfterClose.Status); err != nil {
							log.WithError(err).Warn("Unexpected error updating jira issue.")
							return comment(formatError(fmt.Sprintf("updating to the %s state", options.StateAfterClose.Status), jc.JiraURL(), e.key, err))
						}
						if options.StateAfterClose.Resolution != "" && (bug.Fields.Resolution == nil || !strings.EqualFold(options.StateAfterClose.Resolution, bug.Fields.Resolution.Name)) {
							updateIssue := jira.Issue{Key: bug.Key, Fields: &jira.IssueFields{Resolution: &jira.Resolution{Name: options.StateAfterClose.Resolution}}}
							if _, err := jc.UpdateIssue(&updateIssue); err != nil {
								log.WithError(err).Warn("Unexpected error updating jira issue.")
								return comment(formatError(fmt.Sprintf("updating to the %s resolution", options.StateAfterClose.Resolution), jc.JiraURL(), e.key, err))
							}
						}
						response += fmt.Sprintf(" All external bug links have been closed. The bug has been moved to the %s state.", options.StateAfterClose)
					}
					jiraComment := &jira.Comment{Body: fmt.Sprintf("Bug status changed to %s as previous linked PR https://github.com/%s/%s/pull/%d has been closed", options.StateAfterClose.Status, e.org, e.repo, e.number), Visibility: PrivateVisibility}
					if _, err := jc.AddComment(bug.ID, jiraComment); err != nil {
						response += "\nWarning: Failed to comment on Jira bug with reason for changed state."
					}
				}
			}
		}
		if changed {
			return comment(response)
		}
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

func getBZLabels(bc bugzilla.Client, bug *bugzilla.Bug) ([]string, error) {
	labels := bug.Keywords
	if len(bug.Whiteboard) != 0 {
		labels = append(labels, bug.Whiteboard)
	}
	for _, id := range bug.Blocks {
		blockerBug, err := bc.GetBug(id)
		if err != nil {
			return labels, err
		}
		if len(blockerBug.Alias) != 0 && strings.HasPrefix(blockerBug.Alias[0], "CVE") {
			labels = append(labels, blockerBug.Alias[0])
			labels = append(labels, fmt.Sprintf("flaw:bz#%d", id))
			break
		}
	}
	return labels, nil
}

var bzToJiraComponentMapping = map[string]string{
	"apiserver-auth": "apiserver-auth",
	"Bare Metal Hardware Provisioning/OS Image Provider":          "Bare Metal Hardware Provisioning / OS Image Provider",
	"Bare Metal Hardware Provisioning/baremetal-operator":         "Bare Metal Hardware Provisioning / baremetal-operator",
	"Bare Metal Hardware Provisioning/cluster-api-provider":       "Bare Metal Hardware Provisioning / cluster-api-provider",
	"Bare Metal Hardware Provisioning/cluster-baremetal-operator": "Bare Metal Hardware Provisioning / cluster-baremetal-operator",
	"Bare Metal Hardware Provisioning/ironic":                     "Bare Metal Hardware Provisioning / ironic",
	"Build":                                           "Build",
	"Cloud Compute/Cloud Controller Manager":          "Cloud Compute / Cloud Controller Manager",
	"Cloud Compute/Cluster Autoscaler":                "Cloud Compute / Cluster Autoscaler",
	"Cloud Compute/KubeVirt Provider":                 "Cloud Compute / KubeVirt Provider",
	"Cloud Compute/MachineHealthCheck":                "Cloud Compute / MachineHealthCheck",
	"Cloud Compute/BareMetal Provider":                "Cloud Compute / BareMetal Provider",
	"Cloud Compute/OpenStack Provider":                "Cloud Compute / OpenStack Provider",
	"Cloud Compute/oVirt Providers":                   "Cloud Compute / oVirt Provider",
	"Cloud Compute/Other Providers":                   "Cloud Compute / Other Provider",
	"Cloud Credential Operator":                       "Cloud Credential Operator",
	"Cloud Native Events/Cloud Event Proxy":           "Cloud Native Events / Cloud Event Proxy",
	"Cloud Native Events/Cloud Native Events":         "Cloud Native Events / Cloud Native Events",
	"Cloud Native Events/Hardware Event Proxy":        "Cloud Native Events / Hardware Event Proxy",
	"Cluster Loader":                                  "Cluster Loader",
	"Cluster Version Operator":                        "Cluster Version Operator",
	"CNF Platform Validation":                         "CNF Platform Validation",
	"Compliance Operator":                             "Compliance Operator",
	"config-operator":                                 "config-operator",
	"Console Kubevirt Plugin":                         "Console Kubevirt Plugin",
	"Console Metal3 Plugin":                           "Console Metal3 Plugin",
	"Console Storage Plugin":                          "Console Metal3 Plugin",
	"Containers":                                      "Containers",
	"crc":                                             "crc",
	"Dev Console":                                     "Dev Console",
	"Documentation":                                   "Documentation",
	"Documentation-l10n":                              "Documentation-l10n",
	"Etcd":                                            "Etcd",
	"File Integrity Operator":                         "File Integrity Operator",
	"Hive":                                            "Hive",
	"HyperShift":                                      "HyperShift",
	"ibm-roks-toolkit":                                "ibm-roks-toolkit",
	"Image Registry":                                  "Image Registry",
	"Insights Operator":                               "Insights Operator",
	"Installer/OpenShift on KubeVirt":                 "Installer / OpenShift on KubeVirt",
	"Installer/Single Node OpenShift":                 "Installer / Single Node OpenShift",
	"Installer/OpenShift on Bare Metal IPI":           "Installer / OpenShift on Bare Metal IPI",
	"Installer/OpenShift on OpenStack":                "Installer / OpenShift on OpenStack",
	"Installer/OpenShift on RHV":                      "Installer / OpenShift on RHV",
	"Installer/openshift-ansible":                     "Installer / openshift-ansible",
	"Installer/openshift-installer":                   "Installer / openshift-installer",
	"ISV Operators":                                   "ISV Operators",
	"Jenkins":                                         "Jenkins",
	"kube-apiserver":                                  "kube-apiserver",
	"kube-controller-manager":                         "kube-controller-manager",
	"kube-scheduler":                                  "kube-scheduler",
	"kube-storage-version-migrator":                   "kube-storage-version-migrator",
	"Logging":                                         "Logging",
	"Machine Config Operator/Machine Config Operator": "Machine Config Operator",
	"Machine Config Operator/platform-baremetal":      "Machine Config Operator / platform-baremetal",
	"Machine Config Operator/platform-none":           "Machine Config Operator / platform-none",
	"Machine Config Operator/platform-openstack":      "Machine Config Operator / platform-openstack",
	"Machine Config Operator/platform-ovirt-rhv":      "Machine Config Operator / platform-ovirt-rhv",
	"Machine Config Operator/platform-vsphere":        "Machine Config Operator / platform-vsphere",
	"Management Console":                              "Management Console",
	"Metering Operator":                               "Metering Operator",
	"Monitoring":                                      "Monitoring",
	"Multi-Arch":                                      "Multi-Arch",
	"Networking/Metal LB":                             "Networking / Metal LB",
	"Networking/runtime-cfg":                          "Networking / runtime-cfg",
	"Networking/SR-IOV":                               "Networking / SR-IOV",
	"Networking/kubernetes-nmstate":                   "Networking / kubernetes-nmstate",
	"Networking/kubernetes-nmstate-operator":          "Networking / kubernetes-nmstate-operator",
	"Networking/kuryr":                                "Networking / kuryr",
	"Networking/mDNS":                                 "Networking / mDNS",
	"Networking/multus":                               "Networking / multus",
	"Networking/openshift-sdn":                        "Networking / openshift-sdn",
	"Networking/ovn-kubernetes":                       "Networking / ovn-kubernetes",
	"Networking/ptp":                                  "Networking / ptp",
	"Node/Autoscaler (HPA, VPA)":                      "Node / Autoscaler (HPA, VPA)",
	"Node/CPU manager":                                "Node / CPU manager",
	"Node/CRI-O":                                      "Node / CRI-O",
	"Node/Kubelet":                                    "Node / Kubelet",
	"Node/Memory manager":                             "Node / Memory manager",
	"Node/Numa aware Scheduling":                      "Node / Numa aware Scheduling",
	"Node/Pod resource API":                           "Node / Pod resource API",
	"Node/Topology manager":                           "Node / Topology manager",
	"Node Feature Discovery Operator":                 "Node Feature Discovery Operator",
	"Node Maintenance Operator":                       "Node Maintenance Operator",
	"Node Tuning Operator":                            "Node Tuning Operator",
	"oauth-apiserver":                                 "oauth-apiserver",
	"oauth-proxy":                                     "oauth-proxy",
	"oc":                                              "oc",
	"oc-compliance":                                   "oc-compliance",
	"OLM/OLM":                                         "OLM",
	"OLM/OperatorHub":                                 "OLM / OperatorHub",
	"OpenShift Update Service/operand":                "OpenShift Update Service / operand",
	"OpenShift Update Service/operator":               "OpenShift Update Service / operator",
	"openshift-apiserver":                             "openshift-apiserver",
	"openshift-controller-manager/apps":               "openshift-controller-manager / apps",
	"openshift-controller-manager/build":              "openshift-controller-manager / build",
	"openshift-controller-manager/controller-manager": "openshift-controller-manager / controller-manager",
	"Operator SDK":                                    "Operator SDK",
	"Performance Addon Operator":                      "Performance Addon Operator",
	"Poison Pill Operator":                            "Poison Pill Operator",
	"Reference Architecture":                          "Reference Architecture",
	"Registry Console":                                "Registry Console",
	"Release":                                         "Release",
	"RHCOS":                                           "RHCOS",
	"sandboxed-containers":                            "sandboxed-containers",
	"Security":                                        "Security",
	"Security Profiles Operator":                      "Security Profiles Operator",
	"Service Catalog":                                 "Service Catalog",
	"service-ca":                                      "service-ca",
	"Storage/Shared Resource CSI Driver":              "Storage / Shared Resource CSI Driver",
	"Storage/Kubernetes":                              "Storage / Kubernetes",
	"Storage/Kubernetes External Components":          "Storage / Kubernetes External Components",
	"Storage/Local Storage Operator":                  "Storage / Local Storage Operator",
	"Storage/OpenStack CSI Drivers":                   "Storage / OpenStack CSI Drivers",
	"Storage/Operators":                               "Storage / Operators",
	"Storage/Storage":                                 "Storage",
	"Storage/oVirt CSI Driver":                        "Storage / oVirt CSI Driver",
	"Telco Edge/HW Event Operator":                    "Telco Edge / HW Event Operator",
	"Telco Edge/RAN":                                  "Telco Edge / RAN",
	"Telco Edge/TALO":                                 "Telco Edge / TALO",
	"Telco Edge/ZTP":                                  "Telco Edge / ZTP",
	"Telemeter":                                       "Telemeter",
	"Templates":                                       "Templates",
	"Test Framework":                                  "Test Framework",
	"Test Infrastructure":                             "Test Infrastructure",
	"Unknown":                                         "Unknown",
	"Windows Containers":                              "Windows Containers",
}
