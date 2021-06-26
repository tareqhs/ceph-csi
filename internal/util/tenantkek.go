/*
Copyright 2019 The Ceph-CSI Authors.

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

package util

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	kmsTypeTenantKey = "tenantkey"
	keyDataName      = "key"
)

// asfsda
type TenantKeyKMS struct {
	tenant       string
	tenantSecret string
}

var _ = RegisterKMSProvider(KMSProvider{
	UniqueID:    kmsTypeTenantKey,
	Initializer: initTenantKeyKMS,
})

func initTenantKeyKMS(args KMSInitializerArgs) (EncryptionKMS, error) {
	return &TenantKeyKMS{
		tenant: args.Tenant,
	}, nil
}

func (t *TenantKeyKMS) Destroy() {
}

func (t *TenantKeyKMS) requiresDEKStore() DEKStoreType {
	return DEKStoreMetadata
}

func (t *TenantKeyKMS) EncryptDEK(volumeID, plainDEK string) (string, error) {
	key, err := t.getTenantKey()
	if err != nil {
		return "", err
	}
	return encryptDEKWithPassphrase(volumeID, plainDEK, string(key))
}

func (t *TenantKeyKMS) DecryptDEK(volumeID, encryptedDEK string) (string, error) {
	key, err := t.getTenantKey()
	if err != nil {
		return "", err
	}
	return decryptDEKWithPassphrase(volumeID, encryptedDEK, key)
}

// get the key-encryption-key from the tenant namespace
func (t *TenantKeyKMS) getTenantKey() (string, error) {
	kc := NewK8sClient()
	sec, err := kc.CoreV1().Secrets(t.tenant).Get(context.TODO(), "", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("could not find find tenant secret in namespace %q. %w", t.tenant, err)
	}
	key, ok := sec.Data[keyDataName]
	if !ok {
		return "", fmt.Errorf("could not find data %q in secret %q", keyDataName, t.tenantSecret)
	}
	return string(key), nil
}
