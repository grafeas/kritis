// +build !ignore_autogenerated

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

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1beta1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AttestationAuthority) DeepCopyInto(out *AttestationAuthority) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.PrivateKeySecretName != nil {
		in, out := &in.PrivateKeySecretName, &out.PrivateKeySecretName
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.PublicKeyData != nil {
		in, out := &in.PublicKeyData, &out.PublicKeyData
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AttestationAuthority.
func (in *AttestationAuthority) DeepCopy() *AttestationAuthority {
	if in == nil {
		return nil
	}
	out := new(AttestationAuthority)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AttestationAuthority) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AttestationAuthorityList) DeepCopyInto(out *AttestationAuthorityList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AttestationAuthority, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AttestationAuthorityList.
func (in *AttestationAuthorityList) DeepCopy() *AttestationAuthorityList {
	if in == nil {
		return nil
	}
	out := new(AttestationAuthorityList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AttestationAuthorityList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageSecurityPolicy) DeepCopyInto(out *ImageSecurityPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	if in.ImageWhitelist != nil {
		in, out := &in.ImageWhitelist, &out.ImageWhitelist
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageSecurityPolicy.
func (in *ImageSecurityPolicy) DeepCopy() *ImageSecurityPolicy {
	if in == nil {
		return nil
	}
	out := new(ImageSecurityPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ImageSecurityPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageSecurityPolicyList) DeepCopyInto(out *ImageSecurityPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ImageSecurityPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageSecurityPolicyList.
func (in *ImageSecurityPolicyList) DeepCopy() *ImageSecurityPolicyList {
	if in == nil {
		return nil
	}
	out := new(ImageSecurityPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ImageSecurityPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageSecurityPolicySpec) DeepCopyInto(out *ImageSecurityPolicySpec) {
	*out = *in
	in.PackageVulernerabilityRequirements.DeepCopyInto(&out.PackageVulernerabilityRequirements)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageSecurityPolicySpec.
func (in *ImageSecurityPolicySpec) DeepCopy() *ImageSecurityPolicySpec {
	if in == nil {
		return nil
	}
	out := new(ImageSecurityPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PackageVulernerabilityRequirements) DeepCopyInto(out *PackageVulernerabilityRequirements) {
	*out = *in
	if in.WhitelistCVEs != nil {
		in, out := &in.WhitelistCVEs, &out.WhitelistCVEs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PackageVulernerabilityRequirements.
func (in *PackageVulernerabilityRequirements) DeepCopy() *PackageVulernerabilityRequirements {
	if in == nil {
		return nil
	}
	out := new(PackageVulernerabilityRequirements)
	in.DeepCopyInto(out)
	return out
}
