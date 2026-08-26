/*
Copyright 2026.

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

package controller

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/assert"
)

var _ = Describe("DNS3LIssuer Controller", func() {
})

func TestGetDNS3LCrtName(t *testing.T) {

	assert.Equal(t, "wildcard.foo.bar", getDNS3LCrtName("*.wildcard.foo.bar"))
	assert.Equal(t, "nonwildcard.foo.bar", getDNS3LCrtName("nonwildcard.foo.bar"))
}
