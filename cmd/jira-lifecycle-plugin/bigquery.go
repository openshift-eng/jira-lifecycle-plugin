package main

import (
	"context"
	"errors"

	"cloud.google.com/go/bigquery"
)

const bigqueryTableName = "verified"
const verifyMergeType = "merge"
const verifyLaterType = "later"

type BigQueryInserter interface {
	Put(ctx context.Context, src any) (err error)
}

type fakeBigQueryInserter struct {
	insertedData []VerificationInfo
}

type VerificationInfo struct {
	User   string
	Reason string
	Type   string
	Org    string
	Repo   string
	PRNum  int
	Branch string
}

// Save implements the ValueSaver interface.
func (i *VerificationInfo) Save() (map[string]bigquery.Value, string, error) {
	return map[string]bigquery.Value{
		"User":   i.User,
		"Reason": i.Reason,
		"Type":   i.Type,
		"Org":    i.Org,
		"Repo":   i.Repo,
		"PRNum":  i.PRNum,
		"Branch": i.Branch,
	}, "", nil
}

func (f *fakeBigQueryInserter) Put(ctx context.Context, data any) error {
	info, ok := data.(VerificationInfo)
	if !ok {
		return errors.New("Data is not a VerficationInfo struct")
	}
	f.insertedData = append(f.insertedData, info)
	return nil
}
