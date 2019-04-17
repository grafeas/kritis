package binauthz

import (
	"context"

	"github.com/pkg/errors"
	binaryauthorization "google.golang.org/api/binaryauthorization/v1beta1"
)

type Client interface {
	// GetAttestor gets an Attestor for given name. (name=projects/{projectID}/attestors/{attestorName})
	GetAttestor(ctx context.Context, name string) (*binaryauthorization.Attestor, error)
}

type client struct {
	service *binaryauthorization.Service
}

func New() (Client, error) {
	service, err := binaryauthorization.NewService(
		context.Background(),
	)
	if err != nil {
		return nil, err
	}
	return &client{
		service: service,
	}, nil
}

func (c *client) GetAttestor(ctx context.Context, name string) (*binaryauthorization.Attestor, error) {
	attestorSvc := binaryauthorization.NewProjectsAttestorsService(c.service)
	call := attestorSvc.Get(name).Context(ctx)
	attestor, err := call.Do()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get an attestor: %s", name)
	}
	return attestor, nil
}
