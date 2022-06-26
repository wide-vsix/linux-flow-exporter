/*
Copyright 2022 Hiroki Shirokura.
Copyright 2022 Keio University.
Copyright 2022 Wide Project.

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

package exporter

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

var config ExporterConfig

type ExporterConfig struct {
	Collectors []struct {
		Address string `yaml:"address"`
	} `yaml:"collectors"`
	Templates []struct {
		ID       uint16   `yaml:"id"`
		Template []string `yaml:"template"`
	} `yaml:"templates"`
}

func (cfg *ExporterConfig) Read(filename string) error {
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(yamlFile, cfg)
	if err != nil {
		return err
	}
	return nil
}
