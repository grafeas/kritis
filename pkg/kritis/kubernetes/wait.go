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

package kubernetes

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	apiwatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/watch"
)

func WaitForPodReady(pods corev1.PodInterface, podName string) error {
	logrus.Infof("Waiting for %s to be scheduled", podName)
	err := wait.PollImmediate(time.Millisecond*500, time.Second*10, func() (bool, error) {
		// includeUninitialized was removed, see
		// https://discuss.kubernetes.io/t/kubernetes-initializer-includeuninitialized/5211
		_, err := pods.Get(context.Background(), podName, meta_v1.GetOptions{})
		if err != nil {
			// Debugf, as this generates a log message every 500ms until a pod comes online
			logrus.Debugf("Unable to get pod state for %q: %v", podName, err)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return err
	}

	logrus.Infof("Waiting for %s to be ready", podName)
	return wait.PollImmediate(time.Millisecond*500, time.Minute*5, func() (bool, error) {
		// includeUninitialized was removed, see
		// https://discuss.kubernetes.io/t/kubernetes-initializer-includeuninitialized/5211
		pod, err := pods.Get(context.Background(), podName, meta_v1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("pod not found: %s", podName)
		}
		switch pod.Status.Phase {
		case v1.PodRunning:
			return true, nil
		case v1.PodSucceeded, v1.PodFailed:
			return false, fmt.Errorf("pod already in terminal phase: %s", pod.Status.Phase)
		case v1.PodUnknown, v1.PodPending:
			return false, nil
		}
		return false, fmt.Errorf("unknown phase: %s", pod.Status.Phase)
	})
}

func WaitForPodComplete(pods corev1.PodInterface, podName string) error {
	logrus.Infof("Waiting for %s to be ready", podName)
	return wait.PollImmediate(time.Millisecond*500, time.Minute*5, func() (bool, error) {
		// includeUninitialized was removed, see
		// https://discuss.kubernetes.io/t/kubernetes-initializer-includeuninitialized/5211
		pod, err := pods.Get(context.Background(), podName, meta_v1.GetOptions{})
		if err != nil {
			logrus.Infof("Unable to get pod state for %q: %v", podName, err)
			return false, nil
		}
		switch pod.Status.Phase {
		case v1.PodSucceeded:
			return true, nil
		case v1.PodRunning:
			return false, nil
		case v1.PodFailed:
			return false, fmt.Errorf("pod already in terminal phase: %s", pod.Status.Phase)
		case v1.PodUnknown, v1.PodPending:
			return false, nil
		}
		return false, fmt.Errorf("unknown phase: %s", pod.Status.Phase)
	})
}

type PodStore struct {
	cache.Store
	stopCh    chan struct{}
	Reflector *cache.Reflector
}

func (s *PodStore) List() []*v1.Pod {
	objects := s.Store.List()
	pods := make([]*v1.Pod, 0)
	for _, o := range objects {
		pods = append(pods, o.(*v1.Pod))
	}
	return pods
}

func (s *PodStore) Stop() {
	close(s.stopCh)
}

func NewPodStore(c kubernetes.Interface, namespace string, label fmt.Stringer, field fmt.Stringer) *PodStore {
	lw := &cache.ListWatch{
		ListFunc: func(options meta_v1.ListOptions) (runtime.Object, error) {
			options.LabelSelector = label.String()
			options.FieldSelector = field.String()
			obj, err := c.CoreV1().Pods(namespace).List(context.Background(), options)
			return runtime.Object(obj), err
		},
		WatchFunc: func(options meta_v1.ListOptions) (apiwatch.Interface, error) {
			options.LabelSelector = label.String()
			options.FieldSelector = field.String()
			return c.CoreV1().Pods(namespace).Watch(context.Background(), options)
		},
	}
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	stopCh := make(chan struct{})
	reflector := cache.NewReflector(lw, &v1.Pod{}, store, 0)
	go reflector.Run(stopCh)
	return &PodStore{Store: store, stopCh: stopCh, Reflector: reflector}
}

func StartPods(c kubernetes.Interface, namespace string, pod v1.Pod, waitForRunning bool) error {
	pod.ObjectMeta.Labels["name"] = pod.Name
	if waitForRunning {
		label := labels.SelectorFromSet(labels.Set(map[string]string{"name": pod.Name}))
		err := WaitForPodsWithLabelRunning(c, namespace, label)
		if err != nil {
			return fmt.Errorf("Error waiting for pod %s to be running: %v", pod.Name, err)
		}
	}
	return nil
}

// WaitForPodsWithLabelRunning waits up to 10 minutes for all matching pods to become Running and at least one
// matching pod exists.
func WaitForPodsWithLabelRunning(c kubernetes.Interface, ns string, label labels.Selector) error {
	lastKnownPodNumber := -1
	return wait.PollImmediate(500*time.Millisecond, time.Minute*10, func() (bool, error) {
		listOpts := meta_v1.ListOptions{LabelSelector: label.String()}
		pods, err := c.CoreV1().Pods(ns).List(context.Background(), listOpts)
		if err != nil {
			glog.Infof("error getting pods with label selector %q [%v]\n", label.String(), err)
			return false, nil
		}

		if lastKnownPodNumber != len(pods.Items) {
			glog.Infof("Found %d pods for label selector %s\n", len(pods.Items), label.String())
			lastKnownPodNumber = len(pods.Items)
		}

		if len(pods.Items) == 0 {
			return false, nil
		}

		for _, pod := range pods.Items {
			if pod.Status.Phase != v1.PodRunning {
				return false, nil
			}
		}

		return true, nil
	})
}

// WaitForRCToStabilize waits till the RC has a matching generation/replica count between spec and status.
func WaitForRCToStabilize(c kubernetes.Interface, ns, name string, timeout time.Duration) error {
	selector := fields.Set{
		"metadata.name":      name,
		"metadata.namespace": ns,
	}.AsSelector()

	lw := cache.NewListWatchFromClient(c.CoreV1().RESTClient(), "replicationcontrollers", ns, selector)

	ctx, cancel := watch.ContextWithOptionalTimeout(context.Background(), timeout)
	defer cancel()

	// Create our watcher to keep an eye on the ReplicaControllers until the
	// timeout or the ReplicaController meets the spec
	_, err := watch.UntilWithSync(ctx, lw, &v1.ReplicationController{}, nil, func(event apiwatch.Event) (bool, error) {
		switch event.Type {
		case apiwatch.Deleted:
			return false, apierrs.NewNotFound(schema.GroupResource{Resource: "replicationcontrollers"}, "")
		}
		switch rc := event.Object.(type) {
		case *v1.ReplicationController:
			if rc.Name == name && rc.Namespace == ns &&
				rc.Generation <= rc.Status.ObservedGeneration &&
				*(rc.Spec.Replicas) == rc.Status.Replicas {
				return true, nil
			}
			glog.Infof("Waiting for rc %s to stabilize, generation %v observed generation %v spec.replicas %d status.replicas %d",
				name, rc.Generation, rc.Status.ObservedGeneration, *(rc.Spec.Replicas), rc.Status.Replicas)
		}
		return false, nil
	})
	return err
}

// WaitForDeploymentToStabilize waits till the Deployment has a matching generation/replica count between spec and status.
func WaitForDeploymentToStabilize(c kubernetes.Interface, ns, name string, timeout time.Duration) error {
	selector := fields.Set{
		"metadata.name":      name,
		"metadata.namespace": ns,
	}.AsSelector()

	lw := cache.NewListWatchFromClient(c.AppsV1().RESTClient(), "deployments", ns, selector)

	ctx, cancel := watch.ContextWithOptionalTimeout(context.Background(), timeout)
	defer cancel()

	// Create our watcher to keep an eye on the Deployment until the timeout or
	// the Deployment meets the spec.
	_, err := watch.UntilWithSync(ctx, lw, &appsv1.Deployment{}, nil, func(event apiwatch.Event) (bool, error) {
		switch event.Type {
		case apiwatch.Deleted:
			return false, apierrs.NewNotFound(schema.GroupResource{Resource: "deployments"}, "")
		}
		switch dp := event.Object.(type) {
		case *appsv1.Deployment:
			if dp.Name == name && dp.Namespace == ns &&
				dp.Generation <= dp.Status.ObservedGeneration &&
				*(dp.Spec.Replicas) == dp.Status.Replicas {
				return true, nil
			}
			glog.Infof("Waiting for deployment %s to stabilize, generation %v observed generation %v spec.replicas %d status.replicas %d",
				name, dp.Generation, dp.Status.ObservedGeneration, *(dp.Spec.Replicas), dp.Status.Replicas)
		}
		return false, nil
	})
	return err
}

// WaitForReplicaSetToStabilize waits till the ReplicaSet has a matching generation/replica count between spec and status.
func WaitForReplicaSetToStabilize(c kubernetes.Interface, ns, name string, timeout time.Duration) error {
	selector := fields.Set{
		"metadata.name":      name,
		"metadata.namespace": ns,
	}.AsSelector()

	lw := cache.NewListWatchFromClient(c.AppsV1().RESTClient(), "replicasets", ns, selector)

	ctx, cancel := watch.ContextWithOptionalTimeout(context.Background(), timeout)
	defer cancel()

	// Create our watcher to keep an eye on the ReplicaSet that matches the
	// namespace and name until the timeout or the ReplicaSet meets the spec
	_, err := watch.UntilWithSync(ctx, lw, &appsv1.ReplicaSet{}, nil, func(event apiwatch.Event) (bool, error) {
		switch event.Type {
		case apiwatch.Deleted:
			return false, apierrs.NewNotFound(schema.GroupResource{Resource: "replicasets"}, "")
		}
		switch rs := event.Object.(type) {
		case *appsv1.ReplicaSet:
			if rs.Name == name && rs.Namespace == ns &&
				rs.Generation <= rs.Status.ObservedGeneration &&
				*(rs.Spec.Replicas) == rs.Status.Replicas {
				return true, nil
			}
			glog.Infof("Waiting for replicaset %s to stabilize, generation %v observed generation %v spec.replicas %d status.replicas %d",
				name, rs.Generation, rs.Status.ObservedGeneration, *(rs.Spec.Replicas), rs.Status.Replicas)
		}
		return false, nil
	})
	return err
}

// WaitForService waits until the service appears (exist == true), or disappears (exist == false)
func WaitForService(c kubernetes.Interface, namespace, name string, exist bool, interval, timeout time.Duration) error {
	err := wait.PollImmediate(interval, timeout, func() (bool, error) {
		_, err := c.CoreV1().Services(namespace).Get(context.Background(), name, meta_v1.GetOptions{})
		switch {
		case err == nil:
			glog.Infof("Service %s in namespace %s found.", name, namespace)
			return exist, nil
		case apierrs.IsNotFound(err):
			glog.Infof("Service %s in namespace %s disappeared.", name, namespace)
			return !exist, nil
		case !IsRetryableAPIError(err):
			glog.Infof("Non-retryable failure while getting service.")
			return false, err
		default:
			glog.Infof("Get service %s in namespace %s failed: %v", name, namespace, err)
			return false, nil
		}
	})
	if err != nil {
		stateMsg := map[bool]string{true: "to appear", false: "to disappear"}
		return fmt.Errorf("error waiting for service %s/%s %s: %v", namespace, name, stateMsg[exist], err)
	}
	return nil
}

//WaitForServiceEndpointsNum waits until the amount of endpoints that implement service to expectNum.
func WaitForServiceEndpointsNum(c kubernetes.Interface, namespace, serviceName string, expectNum int, interval, timeout time.Duration) error {
	return wait.Poll(interval, timeout, func() (bool, error) {
		glog.Infof("Waiting for amount of service:%s endpoints to be %d", serviceName, expectNum)
		list, err := c.CoreV1().Endpoints(namespace).List(context.Background(), meta_v1.ListOptions{})
		if err != nil {
			return false, err
		}

		for _, e := range list.Items {
			if e.Name == serviceName && countEndpointsNum(&e) == expectNum {
				return true, nil
			}
		}
		return false, nil
	})
}

func countEndpointsNum(e *v1.Endpoints) int {
	num := 0
	for _, sub := range e.Subsets {
		num += len(sub.Addresses)
	}
	return num
}

func IsRetryableAPIError(err error) bool {
	return apierrs.IsTimeout(err) || apierrs.IsServerTimeout(err) || apierrs.IsTooManyRequests(err) || apierrs.IsInternalError(err)
}
