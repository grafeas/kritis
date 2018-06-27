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

// Code generated by informer-gen. DO NOT EDIT.

package v1beta1

import (
	time "time"

	kritis_v1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	versioned "github.com/grafeas/kritis/pkg/kritis/client/clientset/versioned"
	internalinterfaces "github.com/grafeas/kritis/pkg/kritis/client/informers/externalversions/internalinterfaces"
	v1beta1 "github.com/grafeas/kritis/pkg/kritis/client/listers/kritis/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ImageSecurityPolicyInformer provides access to a shared informer and lister for
// ImageSecurityPolicies.
type ImageSecurityPolicyInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1beta1.ImageSecurityPolicyLister
}

type imageSecurityPolicyInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewImageSecurityPolicyInformer constructs a new informer for ImageSecurityPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewImageSecurityPolicyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredImageSecurityPolicyInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredImageSecurityPolicyInformer constructs a new informer for ImageSecurityPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredImageSecurityPolicyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.KritisV1beta1().ImageSecurityPolicies(namespace).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.KritisV1beta1().ImageSecurityPolicies(namespace).Watch(options)
			},
		},
		&kritis_v1beta1.ImageSecurityPolicy{},
		resyncPeriod,
		indexers,
	)
}

func (f *imageSecurityPolicyInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredImageSecurityPolicyInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *imageSecurityPolicyInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&kritis_v1beta1.ImageSecurityPolicy{}, f.defaultInformer)
}

func (f *imageSecurityPolicyInformer) Lister() v1beta1.ImageSecurityPolicyLister {
	return v1beta1.NewImageSecurityPolicyLister(f.Informer().GetIndexer())
}
