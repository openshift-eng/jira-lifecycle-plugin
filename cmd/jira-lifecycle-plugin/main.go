package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/option"
	prowconfig "sigs.k8s.io/prow/pkg/config"
	"sigs.k8s.io/prow/pkg/config/secret"
	prowflagutil "sigs.k8s.io/prow/pkg/flagutil"
	configflagutil "sigs.k8s.io/prow/pkg/flagutil/config"
	"sigs.k8s.io/prow/pkg/githubeventserver"
	"sigs.k8s.io/prow/pkg/interrupts"
	"sigs.k8s.io/prow/pkg/logrusutil"
	"sigs.k8s.io/prow/pkg/pjutil"
	"sigs.k8s.io/yaml"
)

type options struct {
	mut *sync.RWMutex

	configPath        string
	webhookSecretFile string

	bigqueryEnable     bool
	bigquerySecretFile string
	bigqueryProjectID  string
	bigqueryDatasetID  string

	config *Config

	prowConfig               configflagutil.ConfigOptions
	githubEventServerOptions githubeventserver.Options
	github                   prowflagutil.GitHubOptions
	jira                     prowflagutil.JiraOptions

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

	fs.BoolVar(&o.bigqueryEnable, "enable-bigquery", false, "Enable Big Query verification data uploading.")
	fs.StringVar(&o.bigquerySecretFile, "bigquery-secret-file", "", "Path to credentials file for BigQuery service account.")
	fs.StringVar(&o.bigqueryProjectID, "bigquery-project-id", "", "Name of BigQuery project to operate in.")
	fs.StringVar(&o.bigqueryDatasetID, "bigquery-dataset-id", "", "Name of BigQuery dataset to operate on.")

	o.github.AddFlags(fs)
	o.githubEventServerOptions.Bind(fs)

	o.jira.AddFlags(fs)

	// change config flag name so it doesn't conflict with the plugin's config flah name
	o.prowConfig.ConfigPathFlagName = "prow-config-path"
	o.prowConfig.AddFlags(fs)

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

	bytes, err := ReadFileMaybeGZIP(o.configPath)
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

	if o.bigqueryEnable &&
		(o.bigquerySecretFile == "" || o.bigqueryProjectID == "" || o.bigqueryDatasetID == "") {
		return errors.New("All BigQuery flags must be set to enable Big Query uploading.")
	}

	return nil
}

func (o *options) getConfigWatchAndUpdate() (func(ctx context.Context), error) {
	errFunc := func(err error, msg string) {
		logrus.WithError(err).Error(msg)
	}

	eventFunc := func() error {
		bytes, err := ReadFileMaybeGZIP(o.configPath)
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
		bytes, err := ReadFileMaybeGZIP(o.validateConfig)
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

	var bigqueryClient *bigquery.Client
	if o.bigquerySecretFile != "" {
		bigqueryClient, err = bigquery.NewClient(context.TODO(),
			o.bigqueryProjectID,
			option.WithCredentialsFile(o.bigquerySecretFile),
		)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to create Big Query client")
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

		bigqueryInserter: bigqueryClient.Dataset(o.bigqueryDatasetID).Table(bigqueryTableName).Inserter(),
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
