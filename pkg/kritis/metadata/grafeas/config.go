/*
Copyright 2019 Google LLC

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

package grafeas

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

// file is the Grafeas configuration file.
type file struct {
	GrafeasCerts *CertConfig `yaml:"grafeascerts"`
}

// CertConfig is the Grafeas certificates configuration.
type CertConfig struct {
	CertFile string `yaml:"certfile"` // A PEM encoded certificate file
	KeyFile  string `yaml:"keyfile"`  // A PEM encoded private key file
	CAFile   string `yaml:"cafile"`   // A PEM encoded CA's certificate file
}

// LoadConfig creates a config from a YAML-file. If fileName is an empty
// string a default config will be returned.
func LoadConfig(fileName string) (*CertConfig, error) {
	if fileName == "" {
		return &CertConfig{}, nil
	}

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	var configFile file
	if err := yaml.Unmarshal(data, &configFile); err != nil {
		return nil, err
	}
	config := configFile.GrafeasCerts
	return config, nil
}
