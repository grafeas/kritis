/*
Copyright 2018 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package containeranalysis

import (
	"fmt"
	"math"
	"time"

	gax "github.com/googleapis/gax-go"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
	"google.golang.org/api/transport"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gmetadata "google.golang.org/grpc/metadata"
)

var PKG_VULNERABILITY = "PACKAGE_VULNERABILITY"

// Client is a client for interacting with Container Analysis API.
type Client struct {
	// The connection to the service.
	conn *grpc.ClientConn

	// The gRPC API client.
	client containeranalysispb.ContainerAnalysisClient

	// The call options for this service.
	CallOptions *CallOptions

	// The x-goog-* metadata to be sent with each request.
	xGoogMetadata gmetadata.MD
}

// func defaultClientOptions() []option.ClientOption {
// 	return []option.ClientOption{
// 		option.WithEndpoint("containeranalysis.googleapis.com:443"),
// 		option.WithScopes(DefaultAuthScopes()...),
// 	}
// }

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

func GetClient() (*Client, error) {
	ctx := context.Background()
	conn, err := transport.DialGRPC(ctx)
	if err != nil {
		return nil, err
	}
	c := &Client{
		conn:        conn,
		client:      containeranalysispb.NewContainerAnalysisClient(conn),
		CallOptions: defaultCallOptions(),
	}
	//	c.setGoogleClientInfo()
	return c, nil
}

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

func (c *Client) ListOccurrences(ctx context.Context, req *containeranalysispb.ListOccurrencesRequest, opts ...gax.CallOption) *OccurrenceIterator {
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

func (c *Client) GetVulnerabilities(project string, containerImage string) ([]metadata.Vulnerability, error) {
	vulnz := make([]metadata.Vulnerability, 0)
	ctx := context.Background()
	req := &containeranalysispb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", project),
		Filter: fmt.Sprintf("kind=\"%s\" AND resource_url=\"%s\"", PKG_VULNERABILITY, containerImage),
	}
	it := c.ListOccurrences(ctx, req)
	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		vulnz = append(
			vulnz,
			GetVulnerabilityFromOccurence(occ.GetDetails().(*containeranalysispb.Occurrence_VulnerabilityDetails)))
	}
	return vulnz, nil
}

func GetVulnerabilityFromOccurence(vulnOcc *containeranalysispb.Occurrence_VulnerabilityDetails) metadata.Vulnerability {
	vulnerability := metadata.Vulnerability{
		Severity: string(vulnOcc.VulnerabilityDetails.Severity),
	}
	return vulnerability
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
