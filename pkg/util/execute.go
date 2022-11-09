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

package util

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/fatih/color"
)

var silence = true

func SetLocalExecuteSilence(v bool) {
	silence = v
}

func LocalExecute(cmdstr string) (string, error) {
	stdoutbuf := bytes.Buffer{}
	stderrbuf := bytes.Buffer{}

	cmd := exec.Command("sh", "-c", cmdstr)
	cmd.Stdout = &stdoutbuf
	cmd.Stderr = &stderrbuf

	if err := cmd.Run(); err != nil {
		str := fmt.Sprintf("CommandExecute [%s] ", cmd)
		str += color.RedString("Failed")
		str += color.RedString("%s", err.Error())
		println(str)
		println(stderrbuf.String())
		return "", err
	}

	if !silence {
		str := fmt.Sprintf("CommandExecute [%s] ", cmd)
		str += color.GreenString("Success")
		fmt.Printf("%s\n", str)
	}
	return stdoutbuf.String(), nil
}

func LocalExecutef(fs string, a ...interface{}) (string, error) {
	cmd := fmt.Sprintf(fs, a...)
	return LocalExecute(cmd)
}
