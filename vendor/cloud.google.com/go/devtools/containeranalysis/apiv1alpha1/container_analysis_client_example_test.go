// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// AUTO-GENERATED CODE. DO NOT EDIT.

package containeranalysis_test

import (
	"cloud.google.com/go/devtools/containeranalysis/apiv1alpha1"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
)

func ExampleNewClient() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use client.
	_ = c
}

func ExampleClient_GetOccurrence() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.GetOccurrenceRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.GetOccurrence(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}

func ExampleClient_ListOccurrences() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.ListOccurrencesRequest{
	// TODO: Fill request struct fields.
	}
	it := c.ListOccurrences(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			// TODO: Handle error.
		}
		// TODO: Use resp.
		_ = resp
	}
}

func ExampleClient_DeleteOccurrence() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.DeleteOccurrenceRequest{
	// TODO: Fill request struct fields.
	}
	err = c.DeleteOccurrence(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
}

func ExampleClient_CreateOccurrence() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.CreateOccurrenceRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.CreateOccurrence(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}

func ExampleClient_UpdateOccurrence() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.UpdateOccurrenceRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.UpdateOccurrence(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}

func ExampleClient_GetOccurrenceNote() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.GetOccurrenceNoteRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.GetOccurrenceNote(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}

func ExampleClient_GetNote() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.GetNoteRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.GetNote(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}

func ExampleClient_ListNotes() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.ListNotesRequest{
	// TODO: Fill request struct fields.
	}
	it := c.ListNotes(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			// TODO: Handle error.
		}
		// TODO: Use resp.
		_ = resp
	}
}

func ExampleClient_DeleteNote() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.DeleteNoteRequest{
	// TODO: Fill request struct fields.
	}
	err = c.DeleteNote(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
}

func ExampleClient_CreateNote() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.CreateNoteRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.CreateNote(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}

func ExampleClient_UpdateNote() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.UpdateNoteRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.UpdateNote(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}

func ExampleClient_ListNoteOccurrences() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.ListNoteOccurrencesRequest{
	// TODO: Fill request struct fields.
	}
	it := c.ListNoteOccurrences(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			// TODO: Handle error.
		}
		// TODO: Use resp.
		_ = resp
	}
}

func ExampleClient_GetVulnzOccurrencesSummary() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &containeranalysispb.GetVulnzOccurrencesSummaryRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.GetVulnzOccurrencesSummary(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}

func ExampleClient_SetIamPolicy() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &iampb.SetIamPolicyRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.SetIamPolicy(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}

func ExampleClient_GetIamPolicy() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &iampb.GetIamPolicyRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.GetIamPolicy(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}

func ExampleClient_TestIamPermissions() {
	ctx := context.Background()
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	req := &iampb.TestIamPermissionsRequest{
	// TODO: Fill request struct fields.
	}
	resp, err := c.TestIamPermissions(ctx, req)
	if err != nil {
		// TODO: Handle error.
	}
	// TODO: Use resp.
	_ = resp
}
