package main

import (
	"context"
	"errors"
	"time"

	"cloud.google.com/go/bigquery"
)

const (
	bigqueryTableName     = "verified"
	verifyMergeType       = "merge"
	verifyLaterType       = "later"
	verifyRemoveType      = "remove"
	verifyRemoveLaterType = "removeLater"
	verifyBypassType      = "bypass"
)

type BigQueryInserter interface {
	Put(ctx context.Context, src any) (err error)
}

type fakeBigQueryInserter struct {
	insertedData []VerificationInfo
}

type VerificationInfo struct {
	User      string
	Reason    string
	Type      string
	Org       string
	Repo      string
	PRNum     int
	Branch    string
	Timestamp time.Time
	Link      string
}

// Save implements the ValueSaver interface.
func (i *VerificationInfo) Save() (map[string]bigquery.Value, string, error) {
	return map[string]bigquery.Value{
		"User":      i.User,
		"Reason":    i.Reason,
		"Type":      i.Type,
		"Org":       i.Org,
		"Repo":      i.Repo,
		"PRNum":     i.PRNum,
		"Branch":    i.Branch,
		"Timestamp": i.Timestamp,
		"Link":      i.Link,
	}, "", nil
}

func (f *fakeBigQueryInserter) Put(ctx context.Context, data any) error {
	info, ok := data.(VerificationInfo)
	if !ok {
		return errors.New("Data is not a VerficationInfo struct")
	}
	if info.Timestamp.IsZero() {
		return errors.New("Time is unset")
	}
	// set time of struct to zero for unit tests
	info.Timestamp = time.Time{}
	f.insertedData = append(f.insertedData, info)
	return nil
}
