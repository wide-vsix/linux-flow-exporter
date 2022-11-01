/*
Copyright 2022 Hiroki Shirokura.
Copyright 2022 LINE Corporation.

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

package hook

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type Shell string

var _ Hook = (*Shell)(nil)

func (s Shell) Execute(in map[string]interface{}) (map[string]interface{}, error) {
	// Create temp file from hook shell script
	hash := sha1.New()
	hash.Write([]byte(s))
	filename := fmt.Sprintf("/tmp/%x.sh", hash.Sum(nil))
	if err := os.WriteFile(filename, []byte(s), 0755); err != nil {
		return nil, err
	}

	// Prepare input/output
	stdoutbuf := bytes.Buffer{}
	stderrbuf := bytes.Buffer{}
	stdinbytes, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	// Execute child process
	cmd := exec.Command(filename)
	cmd.Stdout = &stdoutbuf
	cmd.Stderr = &stderrbuf
	cmd.Stdin = bytes.NewBuffer(stdinbytes)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("child process is failed: err=%v stderr=%s",
			err, stderrbuf.String())
	}

	// Convert back to map data from json-bytes
	out := map[string]interface{}{}
	if err := json.Unmarshal(stdoutbuf.Bytes(), &out); err != nil {
		return nil, err
	}
	return out, nil
}
