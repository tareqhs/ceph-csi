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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	kmsTypeStoreHttp = "storehttp"
)

type storeHttpKms struct {
	integratedDEK
	client   *http.Client
	endpoint string
}

type storeKeyRequest struct {
	Key      string `json:"key"`
	VolumeID string `json:"volumeid"`
}
type fetchKeyResponse struct {
	Key string `json:"key"`
}

var _ = RegisterKMSProvider(KMSProvider{
	UniqueID:    kmsTypeVault,
	Initializer: initStoreHttpKms,
})

var _ DEKStore = &storeHttpKms{}

// InitVaultKMS returns an interface to HashiCorp Vault KMS.
func initStoreHttpKms(args KMSInitializerArgs) (EncryptionKMS, error) {
	return &storeHttpKms{}, nil
}

func (t *storeHttpKms) Destroy() {
}

func (t *storeHttpKms) StoreDEK(volumeID string, dek string) error {
	payload, err := json.Marshal(storeKeyRequest{
		VolumeID: volumeID,
		Key:      dek,
	})
	if err != nil {
		return err
	}
	return t.handleNoResponse(
		http.MethodPost,
		t.endpoint,
		bytes.NewReader(payload),
	)
}

func (t *storeHttpKms) FetchDEK(volumeID string) (string, error) {
	var data fetchKeyResponse
	err := t.handleResponse(
		http.MethodGet,
		t.endpoint+"/"+volumeID,
		nil,
		func(resp *http.Response) error {
			return json.NewDecoder(resp.Body).Decode(&data)
		},
	)
	if err != nil {
		return "", err
	}
	return data.Key, nil
}

func (t *storeHttpKms) RemoveDEK(volumeID string) error {
	return t.handleNoResponse(
		http.MethodDelete,
		t.endpoint+"/"+volumeID,
		nil,
	)
}

func (t *storeHttpKms) handleNoResponse(method string, url string, body io.Reader) error {
	return t.handleResponse(method, url, body,
		func(*http.Response) error { return nil })
}

func (t *storeHttpKms) handleResponse(method string, url string, body io.Reader, hf func(*http.Response) error) error {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("bad response %s", resp.Status)
	}
	return hf(resp)
}
