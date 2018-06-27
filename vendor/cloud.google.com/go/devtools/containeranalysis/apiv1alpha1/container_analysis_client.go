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

package containeranalysis

import (
	"math"
	"time"

	gax "github.com/googleapis/gax-go"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/api/transport"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// CallOptions contains the retry settings for each method of Client.
type CallOptions struct {
	GetOccurrence              []gax.CallOption
	ListOccurrences            []gax.CallOption
	DeleteOccurrence           []gax.CallOption
	CreateOccurrence           []gax.CallOption
	UpdateOccurrence           []gax.CallOption
	GetOccurrenceNote          []gax.CallOption
	GetNote                    []gax.CallOption
	ListNotes                  []gax.CallOption
	DeleteNote                 []gax.CallOption
	CreateNote                 []gax.CallOption
	UpdateNote                 []gax.CallOption
	ListNoteOccurrences        []gax.CallOption
	GetVulnzOccurrencesSummary []gax.CallOption
	SetIamPolicy               []gax.CallOption
	GetIamPolicy               []gax.CallOption
	TestIamPermissions         []gax.CallOption
}

func defaultClientOptions() []option.ClientOption {
	return []option.ClientOption{
		option.WithEndpoint("containeranalysis.googleapis.com:443"),
		option.WithScopes(DefaultAuthScopes()...),
	}
}

func defaultCallOptions() *CallOptions {
	retry := map[[2]string][]gax.CallOption{
		{"default", "idempotent"}: {
			gax.WithRetry(func() gax.Retryer {
				return gax.OnCodes([]codes.Code{
					codes.DeadlineExceeded,
					codes.Unavailable,
				}, gax.Backoff{
					Initial:    100 * time.Millisecond,
					Max:        60000 * time.Millisecond,
					Multiplier: 1.3,
				})
			}),
		},
	}
	return &CallOptions{
		GetOccurrence:              retry[[2]string{"default", "idempotent"}],
		ListOccurrences:            retry[[2]string{"default", "idempotent"}],
		DeleteOccurrence:           retry[[2]string{"default", "idempotent"}],
		CreateOccurrence:           retry[[2]string{"default", "non_idempotent"}],
		UpdateOccurrence:           retry[[2]string{"default", "non_idempotent"}],
		GetOccurrenceNote:          retry[[2]string{"default", "idempotent"}],
		GetNote:                    retry[[2]string{"default", "idempotent"}],
		ListNotes:                  retry[[2]string{"default", "idempotent"}],
		DeleteNote:                 retry[[2]string{"default", "idempotent"}],
		CreateNote:                 retry[[2]string{"default", "non_idempotent"}],
		UpdateNote:                 retry[[2]string{"default", "non_idempotent"}],
		ListNoteOccurrences:        retry[[2]string{"default", "idempotent"}],
		GetVulnzOccurrencesSummary: retry[[2]string{"default", "idempotent"}],
		SetIamPolicy:               retry[[2]string{"default", "non_idempotent"}],
		GetIamPolicy:               retry[[2]string{"default", "non_idempotent"}],
		TestIamPermissions:         retry[[2]string{"default", "non_idempotent"}],
	}
}

// Client is a client for interacting with Container Analysis API.
type Client struct {
	// The connection to the service.
	conn *grpc.ClientConn

	// The gRPC API client.
	client containeranalysispb.ContainerAnalysisClient

	// The call options for this service.
	CallOptions *CallOptions

	// The x-goog-* metadata to be sent with each request.
	xGoogMetadata metadata.MD
}

// NewClient creates a new container analysis client.
//
// Retrieves the results of vulnerability scanning of cloud components such as
// container images. The Container Analysis API is an implementation of the
// Grafeas (at grafeas.io) API.
//
// The vulnerability results are stored as a series of Occurrences.
// An Occurrence contains information about a specific vulnerability in a
// resource. An Occurrence references a Note. A Note contains details
// about the vulnerability and is stored in a stored in a separate project.
// Multiple Occurrences can reference the same Note. For example, an SSL
// vulnerability could affect multiple packages in an image. In this case,
// there would be one Note for the vulnerability and an Occurrence for
// each package with the vulnerability referencing that Note.
func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	conn, err := transport.DialGRPC(ctx, append(defaultClientOptions(), opts...)...)
	if err != nil {
		return nil, err
	}
	c := &Client{
		conn:        conn,
		CallOptions: defaultCallOptions(),

		client: containeranalysispb.NewContainerAnalysisClient(conn),
	}
	c.setGoogleClientInfo()
	return c, nil
}

// Connection returns the client's connection to the API service.
func (c *Client) Connection() *grpc.ClientConn {
	return c.conn
}

// Close closes the connection to the API service. The user should invoke this when
// the client is no longer required.
func (c *Client) Close() error {
	return c.conn.Close()
}

// setGoogleClientInfo sets the name and version of the application in
// the `x-goog-api-client` header passed on each request. Intended for
// use by Google-written clients.
func (c *Client) setGoogleClientInfo(keyval ...string) {
	kv := append([]string{"gax", gax.Version, "grpc", grpc.Version}, keyval...)
	c.xGoogMetadata = metadata.Pairs("x-goog-api-client", gax.XGoogHeader(kv...))
}

// GetOccurrence returns the requested Occurrence.
func (c *Client) GetOccurrence(ctx context.Context, req *containeranalysispb.GetOccurrenceRequest, opts ...gax.CallOption) (*containeranalysispb.Occurrence, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.GetOccurrence[0:len(c.CallOptions.GetOccurrence):len(c.CallOptions.GetOccurrence)], opts...)
	var resp *containeranalysispb.Occurrence
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.GetOccurrence(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ListOccurrences lists active Occurrences for a given project matching the filters.
func (c *Client) ListOccurrences(ctx context.Context, req *containeranalysispb.ListOccurrencesRequest, opts ...gax.CallOption) *OccurrenceIterator {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.ListOccurrences[0:len(c.CallOptions.ListOccurrences):len(c.CallOptions.ListOccurrences)], opts...)
	it := &OccurrenceIterator{}
	it.InternalFetch = func(pageSize int, pageToken string) ([]*containeranalysispb.Occurrence, string, error) {
		var resp *containeranalysispb.ListOccurrencesResponse
		req.PageToken = pageToken
		if pageSize > math.MaxInt32 {
			req.PageSize = math.MaxInt32
		} else {
			req.PageSize = int32(pageSize)
		}
		err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
			var err error
			resp, err = c.client.ListOccurrences(ctx, req, settings.GRPC...)
			return err
		}, opts...)
		if err != nil {
			return nil, "", err
		}
		return resp.Occurrences, resp.NextPageToken, nil
	}
	fetch := func(pageSize int, pageToken string) (string, error) {
		items, nextPageToken, err := it.InternalFetch(pageSize, pageToken)
		if err != nil {
			return "", err
		}
		it.items = append(it.items, items...)
		return nextPageToken, nil
	}
	it.pageInfo, it.nextFunc = iterator.NewPageInfo(fetch, it.bufLen, it.takeBuf)
	return it
}

// DeleteOccurrence deletes the given Occurrence from the system. Use this when
// an Occurrence is no longer applicable for the given resource.
func (c *Client) DeleteOccurrence(ctx context.Context, req *containeranalysispb.DeleteOccurrenceRequest, opts ...gax.CallOption) error {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.DeleteOccurrence[0:len(c.CallOptions.DeleteOccurrence):len(c.CallOptions.DeleteOccurrence)], opts...)
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		_, err = c.client.DeleteOccurrence(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	return err
}

// CreateOccurrence creates a new Occurrence. Use this method to create Occurrences
// for a resource.
func (c *Client) CreateOccurrence(ctx context.Context, req *containeranalysispb.CreateOccurrenceRequest, opts ...gax.CallOption) (*containeranalysispb.Occurrence, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.CreateOccurrence[0:len(c.CallOptions.CreateOccurrence):len(c.CallOptions.CreateOccurrence)], opts...)
	var resp *containeranalysispb.Occurrence
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.CreateOccurrence(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateOccurrence updates an existing occurrence.
func (c *Client) UpdateOccurrence(ctx context.Context, req *containeranalysispb.UpdateOccurrenceRequest, opts ...gax.CallOption) (*containeranalysispb.Occurrence, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.UpdateOccurrence[0:len(c.CallOptions.UpdateOccurrence):len(c.CallOptions.UpdateOccurrence)], opts...)
	var resp *containeranalysispb.Occurrence
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.UpdateOccurrence(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetOccurrenceNote gets the Note attached to the given Occurrence.
func (c *Client) GetOccurrenceNote(ctx context.Context, req *containeranalysispb.GetOccurrenceNoteRequest, opts ...gax.CallOption) (*containeranalysispb.Note, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.GetOccurrenceNote[0:len(c.CallOptions.GetOccurrenceNote):len(c.CallOptions.GetOccurrenceNote)], opts...)
	var resp *containeranalysispb.Note
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.GetOccurrenceNote(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetNote returns the requested Note.
func (c *Client) GetNote(ctx context.Context, req *containeranalysispb.GetNoteRequest, opts ...gax.CallOption) (*containeranalysispb.Note, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.GetNote[0:len(c.CallOptions.GetNote):len(c.CallOptions.GetNote)], opts...)
	var resp *containeranalysispb.Note
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.GetNote(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ListNotes lists all Notes for a given project.
func (c *Client) ListNotes(ctx context.Context, req *containeranalysispb.ListNotesRequest, opts ...gax.CallOption) *NoteIterator {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.ListNotes[0:len(c.CallOptions.ListNotes):len(c.CallOptions.ListNotes)], opts...)
	it := &NoteIterator{}
	it.InternalFetch = func(pageSize int, pageToken string) ([]*containeranalysispb.Note, string, error) {
		var resp *containeranalysispb.ListNotesResponse
		req.PageToken = pageToken
		if pageSize > math.MaxInt32 {
			req.PageSize = math.MaxInt32
		} else {
			req.PageSize = int32(pageSize)
		}
		err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
			var err error
			resp, err = c.client.ListNotes(ctx, req, settings.GRPC...)
			return err
		}, opts...)
		if err != nil {
			return nil, "", err
		}
		return resp.Notes, resp.NextPageToken, nil
	}
	fetch := func(pageSize int, pageToken string) (string, error) {
		items, nextPageToken, err := it.InternalFetch(pageSize, pageToken)
		if err != nil {
			return "", err
		}
		it.items = append(it.items, items...)
		return nextPageToken, nil
	}
	it.pageInfo, it.nextFunc = iterator.NewPageInfo(fetch, it.bufLen, it.takeBuf)
	return it
}

// DeleteNote deletes the given Note from the system.
func (c *Client) DeleteNote(ctx context.Context, req *containeranalysispb.DeleteNoteRequest, opts ...gax.CallOption) error {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.DeleteNote[0:len(c.CallOptions.DeleteNote):len(c.CallOptions.DeleteNote)], opts...)
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		_, err = c.client.DeleteNote(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	return err
}

// CreateNote creates a new Note.
func (c *Client) CreateNote(ctx context.Context, req *containeranalysispb.CreateNoteRequest, opts ...gax.CallOption) (*containeranalysispb.Note, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.CreateNote[0:len(c.CallOptions.CreateNote):len(c.CallOptions.CreateNote)], opts...)
	var resp *containeranalysispb.Note
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.CreateNote(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateNote updates an existing Note.
func (c *Client) UpdateNote(ctx context.Context, req *containeranalysispb.UpdateNoteRequest, opts ...gax.CallOption) (*containeranalysispb.Note, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.UpdateNote[0:len(c.CallOptions.UpdateNote):len(c.CallOptions.UpdateNote)], opts...)
	var resp *containeranalysispb.Note
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.UpdateNote(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ListNoteOccurrences lists Occurrences referencing the specified Note. Use this method to
// get all occurrences referencing your Note across all your customer
// projects.
func (c *Client) ListNoteOccurrences(ctx context.Context, req *containeranalysispb.ListNoteOccurrencesRequest, opts ...gax.CallOption) *OccurrenceIterator {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.ListNoteOccurrences[0:len(c.CallOptions.ListNoteOccurrences):len(c.CallOptions.ListNoteOccurrences)], opts...)
	it := &OccurrenceIterator{}
	it.InternalFetch = func(pageSize int, pageToken string) ([]*containeranalysispb.Occurrence, string, error) {
		var resp *containeranalysispb.ListNoteOccurrencesResponse
		req.PageToken = pageToken
		if pageSize > math.MaxInt32 {
			req.PageSize = math.MaxInt32
		} else {
			req.PageSize = int32(pageSize)
		}
		err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
			var err error
			resp, err = c.client.ListNoteOccurrences(ctx, req, settings.GRPC...)
			return err
		}, opts...)
		if err != nil {
			return nil, "", err
		}
		return resp.Occurrences, resp.NextPageToken, nil
	}
	fetch := func(pageSize int, pageToken string) (string, error) {
		items, nextPageToken, err := it.InternalFetch(pageSize, pageToken)
		if err != nil {
			return "", err
		}
		it.items = append(it.items, items...)
		return nextPageToken, nil
	}
	it.pageInfo, it.nextFunc = iterator.NewPageInfo(fetch, it.bufLen, it.takeBuf)
	return it
}

// GetVulnzOccurrencesSummary gets a summary of the number and severity of occurrences.
func (c *Client) GetVulnzOccurrencesSummary(ctx context.Context, req *containeranalysispb.GetVulnzOccurrencesSummaryRequest, opts ...gax.CallOption) (*containeranalysispb.GetVulnzOccurrencesSummaryResponse, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.GetVulnzOccurrencesSummary[0:len(c.CallOptions.GetVulnzOccurrencesSummary):len(c.CallOptions.GetVulnzOccurrencesSummary)], opts...)
	var resp *containeranalysispb.GetVulnzOccurrencesSummaryResponse
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.GetVulnzOccurrencesSummary(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// SetIamPolicy sets the access control policy on the specified Note or Occurrence.
// Requires containeranalysis.notes.setIamPolicy or
// containeranalysis.occurrences.setIamPolicy permission if the resource is
// a Note or an Occurrence, respectively.
// Attempting to call this method without these permissions will result in a PERMISSION_DENIEDerror. Attempting to call this method on a non-existent resource will result in aNOT_FOUNDerror if the user hascontaineranalysis.notes.listpermission on aNoteorcontaineranalysis.occurrences.liston anOccurrence, or aPERMISSION_DENIEDerror otherwise. The resource takes the following formats:projects/{projectid}/occurrences/{occurrenceid}` for occurrences
// and projects/{projectid}/notes/{noteid} for notes
func (c *Client) SetIamPolicy(ctx context.Context, req *iampb.SetIamPolicyRequest, opts ...gax.CallOption) (*iampb.Policy, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.SetIamPolicy[0:len(c.CallOptions.SetIamPolicy):len(c.CallOptions.SetIamPolicy)], opts...)
	var resp *iampb.Policy
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.SetIamPolicy(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetIamPolicy gets the access control policy for a note or an Occurrence resource.
// Requires containeranalysis.notes.setIamPolicy or
// containeranalysis.occurrences.setIamPolicy permission if the resource is
// a note or occurrence, respectively.
// Attempting to call this method on a resource without the required
// permission will result in a PERMISSION_DENIED error. Attempting to call
// this method on a non-existent resource will result in a NOT_FOUND error
// if the user has list permission on the project, or a PERMISSION_DENIED
// error otherwise. The resource takes the following formats:
// projects/{PROJECT_ID}/occurrences/{OCCURRENCE_ID} for occurrences and
// projects/{PROJECT_ID}/notes/{NOTE_ID} for notes
func (c *Client) GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest, opts ...gax.CallOption) (*iampb.Policy, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.GetIamPolicy[0:len(c.CallOptions.GetIamPolicy):len(c.CallOptions.GetIamPolicy)], opts...)
	var resp *iampb.Policy
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.GetIamPolicy(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// TestIamPermissions returns the permissions that a caller has on the specified note or
// occurrence resource. Requires list permission on the project (for example,
// "storage.objects.list" on the containing bucket for testing permission of
// an object). Attempting to call this method on a non-existent resource will
// result in a NOT_FOUND error if the user has list permission on the
// project, or a PERMISSION_DENIED error otherwise. The resource takes the
// following formats: projects/{PROJECT_ID}/occurrences/{OCCURRENCE_ID} for
// Occurrences and projects/{PROJECT_ID}/notes/{NOTE_ID} for Notes
func (c *Client) TestIamPermissions(ctx context.Context, req *iampb.TestIamPermissionsRequest, opts ...gax.CallOption) (*iampb.TestIamPermissionsResponse, error) {
	ctx = insertMetadata(ctx, c.xGoogMetadata)
	opts = append(c.CallOptions.TestIamPermissions[0:len(c.CallOptions.TestIamPermissions):len(c.CallOptions.TestIamPermissions)], opts...)
	var resp *iampb.TestIamPermissionsResponse
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.client.TestIamPermissions(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// NoteIterator manages a stream of *containeranalysispb.Note.
type NoteIterator struct {
	items    []*containeranalysispb.Note
	pageInfo *iterator.PageInfo
	nextFunc func() error

	// InternalFetch is for use by the Google Cloud Libraries only.
	// It is not part of the stable interface of this package.
	//
	// InternalFetch returns results from a single call to the underlying RPC.
	// The number of results is no greater than pageSize.
	// If there are no more results, nextPageToken is empty and err is nil.
	InternalFetch func(pageSize int, pageToken string) (results []*containeranalysispb.Note, nextPageToken string, err error)
}

// PageInfo supports pagination. See the google.golang.org/api/iterator package for details.
func (it *NoteIterator) PageInfo() *iterator.PageInfo {
	return it.pageInfo
}

// Next returns the next result. Its second return value is iterator.Done if there are no more
// results. Once Next returns Done, all subsequent calls will return Done.
func (it *NoteIterator) Next() (*containeranalysispb.Note, error) {
	var item *containeranalysispb.Note
	if err := it.nextFunc(); err != nil {
		return item, err
	}
	item = it.items[0]
	it.items = it.items[1:]
	return item, nil
}

func (it *NoteIterator) bufLen() int {
	return len(it.items)
}

func (it *NoteIterator) takeBuf() interface{} {
	b := it.items
	it.items = nil
	return b
}

// OccurrenceIterator manages a stream of *containeranalysispb.Occurrence.
type OccurrenceIterator struct {
	items    []*containeranalysispb.Occurrence
	pageInfo *iterator.PageInfo
	nextFunc func() error

	// InternalFetch is for use by the Google Cloud Libraries only.
	// It is not part of the stable interface of this package.
	//
	// InternalFetch returns results from a single call to the underlying RPC.
	// The number of results is no greater than pageSize.
	// If there are no more results, nextPageToken is empty and err is nil.
	InternalFetch func(pageSize int, pageToken string) (results []*containeranalysispb.Occurrence, nextPageToken string, err error)
}

// PageInfo supports pagination. See the google.golang.org/api/iterator package for details.
func (it *OccurrenceIterator) PageInfo() *iterator.PageInfo {
	return it.pageInfo
}

// Next returns the next result. Its second return value is iterator.Done if there are no more
// results. Once Next returns Done, all subsequent calls will return Done.
func (it *OccurrenceIterator) Next() (*containeranalysispb.Occurrence, error) {
	var item *containeranalysispb.Occurrence
	if err := it.nextFunc(); err != nil {
		return item, err
	}
	item = it.items[0]
	it.items = it.items[1:]
	return item, nil
}

func (it *OccurrenceIterator) bufLen() int {
	return len(it.items)
}

func (it *OccurrenceIterator) takeBuf() interface{} {
	b := it.items
	it.items = nil
	return b
}
