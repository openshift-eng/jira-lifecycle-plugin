package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/test-infra/prow/bugzilla"
	prowconfig "k8s.io/test-infra/prow/config"
	"k8s.io/test-infra/prow/config/secret"
	prowflagutil "k8s.io/test-infra/prow/flagutil"
	configflagutil "k8s.io/test-infra/prow/flagutil/config"
	"k8s.io/test-infra/prow/githubeventserver"
	"k8s.io/test-infra/prow/interrupts"
	"k8s.io/test-infra/prow/logrusutil"
	"k8s.io/test-infra/prow/pjutil"
	"sigs.k8s.io/yaml"

	"github.com/openshift/ci-tools/pkg/util/gzip"
)

type options struct {
	mut *sync.RWMutex

	configPath        string
	webhookSecretFile string

	config *Config

	prowConfig               configflagutil.ConfigOptions
	githubEventServerOptions githubeventserver.Options
	github                   prowflagutil.GitHubOptions
	jira                     prowflagutil.JiraOptions
	bugzilla                 prowflagutil.BugzillaOptions

	validateConfig string
}

func gatherOptions() options {
	o := options{
		mut: &sync.RWMutex{},
	}
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	fs.StringVar(&o.configPath, "config-path", "", "Path to jira lifecycle configuration.")
	fs.StringVar(&o.validateConfig, "validate-config", "", "Validate config at specified directory and exit without running operator")
	fs.StringVar(&o.webhookSecretFile, "hmac-secret-file", "", "Path to the file containing the GitHub HMAC secret.")

	o.github.AddFlags(fs)
	o.githubEventServerOptions.Bind(fs)

	o.jira.AddFlags(fs)

	// change config flag name so it doesn't conflict with the plugin's config flah name
	o.prowConfig.ConfigPathFlagName = "prow-config-path"
	o.prowConfig.AddFlags(fs)
	o.bugzilla.AddFlags(fs)

	if err := fs.Parse(os.Args[1:]); err != nil {
		logrus.WithError(err).Fatalf("cannot parse args: '%s'", os.Args[1:])
	}
	return o
}

func (o *options) Validate() error {
	if err := o.github.Validate(false); err != nil {
		return err
	}

	if err := o.jira.Validate(false); err != nil {
		return err
	}

	bytes, err := gzip.ReadFileMaybeGZIP(o.configPath)
	if err != nil {
		return fmt.Errorf("couldn't read configuration file: %v", o.configPath)
	}

	var config Config
	if err := yaml.Unmarshal(bytes, &config); err != nil {
		return fmt.Errorf("couldn't unmarshal configuration: %w", err)
	}
	o.config = &config

	if err := o.githubEventServerOptions.DefaultAndValidate(); err != nil {
		return err
	}

	return nil
}

func (o *options) getConfigWatchAndUpdate() (func(ctx context.Context), error) {
	errFunc := func(err error, msg string) {
		logrus.WithError(err).Error(msg)
	}

	eventFunc := func() error {
		bytes, err := gzip.ReadFileMaybeGZIP(o.configPath)
		if err != nil {
			return fmt.Errorf("couldn't read configuration file %s: %w", o.configPath, err)
		}

		var c Config
		if err := yaml.Unmarshal(bytes, &c); err != nil {
			return fmt.Errorf("couldn't unmarshal configuration: %w", err)
		}

		o.mut.Lock()
		defer o.mut.Unlock()
		o.config = &c
		logrus.Info("Configuration updated")

		return nil
	}
	watcher, err := prowconfig.GetCMMountWatcher(eventFunc, errFunc, filepath.Dir(o.configPath))
	if err != nil {
		return nil, fmt.Errorf("couldn't get the file watcher: %w", err)
	}

	return watcher, nil
}

func main() {
	logrusutil.ComponentInit()
	logger := logrus.WithField("plugin", "jira-lifecycle")

	o := gatherOptions()
	if o.validateConfig != "" {
		bytes, err := gzip.ReadFileMaybeGZIP(o.validateConfig)
		if err != nil {
			logger.Fatalf("couldn't read configuration file %s: %v", o.configPath, err)
		}
		if err := validateConfig(bytes); err != nil {
			fmt.Printf("Config is invalid: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if err := o.Validate(); err != nil {
		logger.Fatalf("Invalid options: %v", err)
	}

	configWatchAndUpdate, err := o.getConfigWatchAndUpdate()
	if err != nil {
		logger.WithError(err).Fatal("couldn't get config file watch and update function")
	}
	interrupts.Run(configWatchAndUpdate)

	// get prow config
	configAgent, err := o.prowConfig.ConfigAgent()
	if err != nil {
		logger.WithError(err).Fatal("Error starting config agent.")
	}

	var tokens []string

	// Append the path of hmac and github secrets.
	if o.github.TokenPath != "" {
		tokens = append(tokens, o.github.TokenPath)
	}
	if o.github.AppPrivateKeyPath != "" {
		tokens = append(tokens, o.github.AppPrivateKeyPath)
	}
	tokens = append(tokens, o.webhookSecretFile)

	if o.bugzilla.ApiKeyPath != "" {
		tokens = append(tokens, o.bugzilla.ApiKeyPath)
	}

	if err := secret.Add(tokens...); err != nil {
		logrus.WithError(err).Fatal("Error starting secrets agent.")
	}

	githubClient, err := o.github.GitHubClient(false)
	if err != nil {
		logger.WithError(err).Fatal("Error getting GitHub client.")
	}

	jiraClient, err := o.jira.Client()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to construct Jira Client")
	}

	var bzClient bugzilla.Client
	if o.bugzilla.ApiKeyPath != "" {
		bzClient, err = o.bugzilla.BugzillaClient()
		if err != nil {
			logrus.WithError(err).Fatal("Failed to create bugzilla client")
		}
	}

	serv := &server{
		config: func() *Config {
			o.mut.Lock()
			defer o.mut.Unlock()
			return o.config
		},
		ghc:             githubClient.WithFields(logger.Data).ForPlugin(PluginName),
		jc:              jiraClient.WithFields(logger.Data).ForPlugin(PluginName),
		prowConfigAgent: configAgent,
		bc:              bzClient,
	}

	eventServer := githubeventserver.New(o.githubEventServerOptions, secret.GetTokenGenerator(o.webhookSecretFile), logger)
	eventServer.RegisterHandleIssueCommentEvent(serv.handleIssueComment)
	eventServer.RegisterHandlePullRequestEvent(serv.handlePullRequest)
	eventServer.RegisterHelpProvider(serv.helpProvider, logger)

	health := pjutil.NewHealth()
	health.ServeReady()

	interrupts.ListenAndServe(eventServer, time.Second*30)
	interrupts.WaitForGracefulShutdown()
}
