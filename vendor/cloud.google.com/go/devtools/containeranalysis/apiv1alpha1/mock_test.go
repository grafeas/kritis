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
	emptypb "github.com/golang/protobuf/ptypes/empty"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
)

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"golang.org/x/net/context"
	"google.golang.org/api/option"
	status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	gstatus "google.golang.org/grpc/status"
)

var _ = io.EOF
var _ = ptypes.MarshalAny
var _ status.Status

type mockContainerAnalysisServer struct {
	// Embed for forward compatibility.
	// Tests will keep working if more methods are added
	// in the future.
	containeranalysispb.ContainerAnalysisServer

	reqs []proto.Message

	// If set, all calls return this error.
	err error

	// responses to return if err == nil
	resps []proto.Message
}

func (s *mockContainerAnalysisServer) GetOccurrence(ctx context.Context, req *containeranalysispb.GetOccurrenceRequest) (*containeranalysispb.Occurrence, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.Occurrence), nil
}

func (s *mockContainerAnalysisServer) ListOccurrences(ctx context.Context, req *containeranalysispb.ListOccurrencesRequest) (*containeranalysispb.ListOccurrencesResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.ListOccurrencesResponse), nil
}

func (s *mockContainerAnalysisServer) DeleteOccurrence(ctx context.Context, req *containeranalysispb.DeleteOccurrenceRequest) (*emptypb.Empty, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*emptypb.Empty), nil
}

func (s *mockContainerAnalysisServer) CreateOccurrence(ctx context.Context, req *containeranalysispb.CreateOccurrenceRequest) (*containeranalysispb.Occurrence, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.Occurrence), nil
}

func (s *mockContainerAnalysisServer) UpdateOccurrence(ctx context.Context, req *containeranalysispb.UpdateOccurrenceRequest) (*containeranalysispb.Occurrence, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.Occurrence), nil
}

func (s *mockContainerAnalysisServer) GetOccurrenceNote(ctx context.Context, req *containeranalysispb.GetOccurrenceNoteRequest) (*containeranalysispb.Note, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.Note), nil
}

func (s *mockContainerAnalysisServer) GetNote(ctx context.Context, req *containeranalysispb.GetNoteRequest) (*containeranalysispb.Note, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.Note), nil
}

func (s *mockContainerAnalysisServer) ListNotes(ctx context.Context, req *containeranalysispb.ListNotesRequest) (*containeranalysispb.ListNotesResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.ListNotesResponse), nil
}

func (s *mockContainerAnalysisServer) DeleteNote(ctx context.Context, req *containeranalysispb.DeleteNoteRequest) (*emptypb.Empty, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*emptypb.Empty), nil
}

func (s *mockContainerAnalysisServer) CreateNote(ctx context.Context, req *containeranalysispb.CreateNoteRequest) (*containeranalysispb.Note, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.Note), nil
}

func (s *mockContainerAnalysisServer) UpdateNote(ctx context.Context, req *containeranalysispb.UpdateNoteRequest) (*containeranalysispb.Note, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.Note), nil
}

func (s *mockContainerAnalysisServer) ListNoteOccurrences(ctx context.Context, req *containeranalysispb.ListNoteOccurrencesRequest) (*containeranalysispb.ListNoteOccurrencesResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.ListNoteOccurrencesResponse), nil
}

func (s *mockContainerAnalysisServer) GetVulnzOccurrencesSummary(ctx context.Context, req *containeranalysispb.GetVulnzOccurrencesSummaryRequest) (*containeranalysispb.GetVulnzOccurrencesSummaryResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*containeranalysispb.GetVulnzOccurrencesSummaryResponse), nil
}

func (s *mockContainerAnalysisServer) SetIamPolicy(ctx context.Context, req *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*iampb.Policy), nil
}

func (s *mockContainerAnalysisServer) GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*iampb.Policy), nil
}

func (s *mockContainerAnalysisServer) TestIamPermissions(ctx context.Context, req *iampb.TestIamPermissionsRequest) (*iampb.TestIamPermissionsResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if xg := md["x-goog-api-client"]; len(xg) == 0 || !strings.Contains(xg[0], "gl-go/") {
		return nil, fmt.Errorf("x-goog-api-client = %v, expected gl-go key", xg)
	}
	s.reqs = append(s.reqs, req)
	if s.err != nil {
		return nil, s.err
	}
	return s.resps[0].(*iampb.TestIamPermissionsResponse), nil
}

// clientOpt is the option tests should use to connect to the test server.
// It is initialized by TestMain.
var clientOpt option.ClientOption

var (
	mockContainerAnalysis mockContainerAnalysisServer
)

func TestMain(m *testing.M) {
	flag.Parse()

	serv := grpc.NewServer()
	containeranalysispb.RegisterContainerAnalysisServer(serv, &mockContainerAnalysis)

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}
	go serv.Serve(lis)

	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	clientOpt = option.WithGRPCConn(conn)

	os.Exit(m.Run())
}

func TestContainerAnalysisGetOccurrence(t *testing.T) {
	var name2 string = "name2-1052831874"
	var resourceUrl string = "resourceUrl-384040514"
	var noteName string = "noteName1780787896"
	var remediation string = "remediation779381797"
	var expectedResponse = &containeranalysispb.Occurrence{
		Name:        name2,
		ResourceUrl: resourceUrl,
		NoteName:    noteName,
		Remediation: remediation,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedName string = fmt.Sprintf("projects/%s/occurrences/%s", "[PROJECT]", "[OCCURRENCE]")
	var request = &containeranalysispb.GetOccurrenceRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetOccurrence(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisGetOccurrenceError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedName string = fmt.Sprintf("projects/%s/occurrences/%s", "[PROJECT]", "[OCCURRENCE]")
	var request = &containeranalysispb.GetOccurrenceRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetOccurrence(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisListOccurrences(t *testing.T) {
	var nextPageToken string = ""
	var occurrencesElement *containeranalysispb.Occurrence = &containeranalysispb.Occurrence{}
	var occurrences = []*containeranalysispb.Occurrence{occurrencesElement}
	var expectedResponse = &containeranalysispb.ListOccurrencesResponse{
		NextPageToken: nextPageToken,
		Occurrences:   occurrences,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedParent string = fmt.Sprintf("projects/%s", "[PROJECT]")
	var request = &containeranalysispb.ListOccurrencesRequest{
		Parent: formattedParent,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.ListOccurrences(context.Background(), request).Next()

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	want := (interface{})(expectedResponse.Occurrences[0])
	got := (interface{})(resp)
	var ok bool

	switch want := (want).(type) {
	case proto.Message:
		ok = proto.Equal(want, got.(proto.Message))
	default:
		ok = want == got
	}
	if !ok {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisListOccurrencesError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedParent string = fmt.Sprintf("projects/%s", "[PROJECT]")
	var request = &containeranalysispb.ListOccurrencesRequest{
		Parent: formattedParent,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.ListOccurrences(context.Background(), request).Next()

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisDeleteOccurrence(t *testing.T) {
	var expectedResponse *emptypb.Empty = &emptypb.Empty{}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedName string = fmt.Sprintf("projects/%s/occurrences/%s", "[PROJECT]", "[OCCURRENCE]")
	var request = &containeranalysispb.DeleteOccurrenceRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	err = c.DeleteOccurrence(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

}

func TestContainerAnalysisDeleteOccurrenceError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedName string = fmt.Sprintf("projects/%s/occurrences/%s", "[PROJECT]", "[OCCURRENCE]")
	var request = &containeranalysispb.DeleteOccurrenceRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	err = c.DeleteOccurrence(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
}
func TestContainerAnalysisCreateOccurrence(t *testing.T) {
	var name string = "name3373707"
	var resourceUrl string = "resourceUrl-384040514"
	var noteName string = "noteName1780787896"
	var remediation string = "remediation779381797"
	var expectedResponse = &containeranalysispb.Occurrence{
		Name:        name,
		ResourceUrl: resourceUrl,
		NoteName:    noteName,
		Remediation: remediation,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedParent string = fmt.Sprintf("projects/%s", "[PROJECT]")
	var occurrence *containeranalysispb.Occurrence = &containeranalysispb.Occurrence{}
	var request = &containeranalysispb.CreateOccurrenceRequest{
		Parent:     formattedParent,
		Occurrence: occurrence,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.CreateOccurrence(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisCreateOccurrenceError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedParent string = fmt.Sprintf("projects/%s", "[PROJECT]")
	var occurrence *containeranalysispb.Occurrence = &containeranalysispb.Occurrence{}
	var request = &containeranalysispb.CreateOccurrenceRequest{
		Parent:     formattedParent,
		Occurrence: occurrence,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.CreateOccurrence(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisUpdateOccurrence(t *testing.T) {
	var name2 string = "name2-1052831874"
	var resourceUrl string = "resourceUrl-384040514"
	var noteName string = "noteName1780787896"
	var remediation string = "remediation779381797"
	var expectedResponse = &containeranalysispb.Occurrence{
		Name:        name2,
		ResourceUrl: resourceUrl,
		NoteName:    noteName,
		Remediation: remediation,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedName string = fmt.Sprintf("projects/%s/occurrences/%s", "[PROJECT]", "[OCCURRENCE]")
	var occurrence *containeranalysispb.Occurrence = &containeranalysispb.Occurrence{}
	var request = &containeranalysispb.UpdateOccurrenceRequest{
		Name:       formattedName,
		Occurrence: occurrence,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.UpdateOccurrence(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisUpdateOccurrenceError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedName string = fmt.Sprintf("projects/%s/occurrences/%s", "[PROJECT]", "[OCCURRENCE]")
	var occurrence *containeranalysispb.Occurrence = &containeranalysispb.Occurrence{}
	var request = &containeranalysispb.UpdateOccurrenceRequest{
		Name:       formattedName,
		Occurrence: occurrence,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.UpdateOccurrence(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisGetOccurrenceNote(t *testing.T) {
	var name2 string = "name2-1052831874"
	var shortDescription string = "shortDescription-235369287"
	var longDescription string = "longDescription-1747792199"
	var expectedResponse = &containeranalysispb.Note{
		Name:             name2,
		ShortDescription: shortDescription,
		LongDescription:  longDescription,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedName string = fmt.Sprintf("projects/%s/occurrences/%s", "[PROJECT]", "[OCCURRENCE]")
	var request = &containeranalysispb.GetOccurrenceNoteRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetOccurrenceNote(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisGetOccurrenceNoteError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedName string = fmt.Sprintf("projects/%s/occurrences/%s", "[PROJECT]", "[OCCURRENCE]")
	var request = &containeranalysispb.GetOccurrenceNoteRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetOccurrenceNote(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisGetNote(t *testing.T) {
	var name2 string = "name2-1052831874"
	var shortDescription string = "shortDescription-235369287"
	var longDescription string = "longDescription-1747792199"
	var expectedResponse = &containeranalysispb.Note{
		Name:             name2,
		ShortDescription: shortDescription,
		LongDescription:  longDescription,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedName string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var request = &containeranalysispb.GetNoteRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetNote(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisGetNoteError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedName string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var request = &containeranalysispb.GetNoteRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetNote(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisListNotes(t *testing.T) {
	var nextPageToken string = ""
	var notesElement *containeranalysispb.Note = &containeranalysispb.Note{}
	var notes = []*containeranalysispb.Note{notesElement}
	var expectedResponse = &containeranalysispb.ListNotesResponse{
		NextPageToken: nextPageToken,
		Notes:         notes,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedParent string = fmt.Sprintf("projects/%s", "[PROJECT]")
	var request = &containeranalysispb.ListNotesRequest{
		Parent: formattedParent,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.ListNotes(context.Background(), request).Next()

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	want := (interface{})(expectedResponse.Notes[0])
	got := (interface{})(resp)
	var ok bool

	switch want := (want).(type) {
	case proto.Message:
		ok = proto.Equal(want, got.(proto.Message))
	default:
		ok = want == got
	}
	if !ok {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisListNotesError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedParent string = fmt.Sprintf("projects/%s", "[PROJECT]")
	var request = &containeranalysispb.ListNotesRequest{
		Parent: formattedParent,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.ListNotes(context.Background(), request).Next()

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisDeleteNote(t *testing.T) {
	var expectedResponse *emptypb.Empty = &emptypb.Empty{}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedName string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var request = &containeranalysispb.DeleteNoteRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	err = c.DeleteNote(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

}

func TestContainerAnalysisDeleteNoteError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedName string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var request = &containeranalysispb.DeleteNoteRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	err = c.DeleteNote(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
}
func TestContainerAnalysisCreateNote(t *testing.T) {
	var name string = "name3373707"
	var shortDescription string = "shortDescription-235369287"
	var longDescription string = "longDescription-1747792199"
	var expectedResponse = &containeranalysispb.Note{
		Name:             name,
		ShortDescription: shortDescription,
		LongDescription:  longDescription,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedParent string = fmt.Sprintf("projects/%s", "[PROJECT]")
	var noteId string = "noteId2129224840"
	var note *containeranalysispb.Note = &containeranalysispb.Note{}
	var request = &containeranalysispb.CreateNoteRequest{
		Parent: formattedParent,
		NoteId: noteId,
		Note:   note,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.CreateNote(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisCreateNoteError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedParent string = fmt.Sprintf("projects/%s", "[PROJECT]")
	var noteId string = "noteId2129224840"
	var note *containeranalysispb.Note = &containeranalysispb.Note{}
	var request = &containeranalysispb.CreateNoteRequest{
		Parent: formattedParent,
		NoteId: noteId,
		Note:   note,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.CreateNote(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisUpdateNote(t *testing.T) {
	var name2 string = "name2-1052831874"
	var shortDescription string = "shortDescription-235369287"
	var longDescription string = "longDescription-1747792199"
	var expectedResponse = &containeranalysispb.Note{
		Name:             name2,
		ShortDescription: shortDescription,
		LongDescription:  longDescription,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedName string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var note *containeranalysispb.Note = &containeranalysispb.Note{}
	var request = &containeranalysispb.UpdateNoteRequest{
		Name: formattedName,
		Note: note,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.UpdateNote(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisUpdateNoteError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedName string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var note *containeranalysispb.Note = &containeranalysispb.Note{}
	var request = &containeranalysispb.UpdateNoteRequest{
		Name: formattedName,
		Note: note,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.UpdateNote(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisListNoteOccurrences(t *testing.T) {
	var nextPageToken string = ""
	var occurrencesElement *containeranalysispb.Occurrence = &containeranalysispb.Occurrence{}
	var occurrences = []*containeranalysispb.Occurrence{occurrencesElement}
	var expectedResponse = &containeranalysispb.ListNoteOccurrencesResponse{
		NextPageToken: nextPageToken,
		Occurrences:   occurrences,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedName string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var request = &containeranalysispb.ListNoteOccurrencesRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.ListNoteOccurrences(context.Background(), request).Next()

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	want := (interface{})(expectedResponse.Occurrences[0])
	got := (interface{})(resp)
	var ok bool

	switch want := (want).(type) {
	case proto.Message:
		ok = proto.Equal(want, got.(proto.Message))
	default:
		ok = want == got
	}
	if !ok {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisListNoteOccurrencesError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedName string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var request = &containeranalysispb.ListNoteOccurrencesRequest{
		Name: formattedName,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.ListNoteOccurrences(context.Background(), request).Next()

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisGetVulnzOccurrencesSummary(t *testing.T) {
	var expectedResponse *containeranalysispb.GetVulnzOccurrencesSummaryResponse = &containeranalysispb.GetVulnzOccurrencesSummaryResponse{}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedParent string = fmt.Sprintf("projects/%s", "[PROJECT]")
	var request = &containeranalysispb.GetVulnzOccurrencesSummaryRequest{
		Parent: formattedParent,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetVulnzOccurrencesSummary(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisGetVulnzOccurrencesSummaryError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedParent string = fmt.Sprintf("projects/%s", "[PROJECT]")
	var request = &containeranalysispb.GetVulnzOccurrencesSummaryRequest{
		Parent: formattedParent,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetVulnzOccurrencesSummary(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisSetIamPolicy(t *testing.T) {
	var version int32 = 351608024
	var etag []byte = []byte("21")
	var expectedResponse = &iampb.Policy{
		Version: version,
		Etag:    etag,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedResource string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var policy *iampb.Policy = &iampb.Policy{}
	var request = &iampb.SetIamPolicyRequest{
		Resource: formattedResource,
		Policy:   policy,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.SetIamPolicy(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisSetIamPolicyError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedResource string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var policy *iampb.Policy = &iampb.Policy{}
	var request = &iampb.SetIamPolicyRequest{
		Resource: formattedResource,
		Policy:   policy,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.SetIamPolicy(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisGetIamPolicy(t *testing.T) {
	var version int32 = 351608024
	var etag []byte = []byte("21")
	var expectedResponse = &iampb.Policy{
		Version: version,
		Etag:    etag,
	}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedResource string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var request = &iampb.GetIamPolicyRequest{
		Resource: formattedResource,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetIamPolicy(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisGetIamPolicyError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedResource string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var request = &iampb.GetIamPolicyRequest{
		Resource: formattedResource,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetIamPolicy(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
func TestContainerAnalysisTestIamPermissions(t *testing.T) {
	var expectedResponse *iampb.TestIamPermissionsResponse = &iampb.TestIamPermissionsResponse{}

	mockContainerAnalysis.err = nil
	mockContainerAnalysis.reqs = nil

	mockContainerAnalysis.resps = append(mockContainerAnalysis.resps[:0], expectedResponse)

	var formattedResource string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var permissions []string = nil
	var request = &iampb.TestIamPermissionsRequest{
		Resource:    formattedResource,
		Permissions: permissions,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.TestIamPermissions(context.Background(), request)

	if err != nil {
		t.Fatal(err)
	}

	if want, got := request, mockContainerAnalysis.reqs[0]; !proto.Equal(want, got) {
		t.Errorf("wrong request %q, want %q", got, want)
	}

	if want, got := expectedResponse, resp; !proto.Equal(want, got) {
		t.Errorf("wrong response %q, want %q)", got, want)
	}
}

func TestContainerAnalysisTestIamPermissionsError(t *testing.T) {
	errCode := codes.PermissionDenied
	mockContainerAnalysis.err = gstatus.Error(errCode, "test error")

	var formattedResource string = fmt.Sprintf("projects/%s/notes/%s", "[PROJECT]", "[NOTE]")
	var permissions []string = nil
	var request = &iampb.TestIamPermissionsRequest{
		Resource:    formattedResource,
		Permissions: permissions,
	}

	c, err := NewClient(context.Background(), clientOpt)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.TestIamPermissions(context.Background(), request)

	if st, ok := gstatus.FromError(err); !ok {
		t.Errorf("got error %v, expected grpc error", err)
	} else if c := st.Code(); c != errCode {
		t.Errorf("got error code %q, want %q", c, errCode)
	}
	_ = resp
}
