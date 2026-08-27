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
	"github.com/cert-manager/issuer-lib/controllers/signer"
)

type SignMiddleware func(next signer.Sign) signer.Sign

func SignMiddlewareChain(s signer.Sign, middlewares ...SignMiddleware) *MiddlewareChain {
	return &MiddlewareChain{
		sign:        s,
		middlewares: middlewares,
	}
}

type MiddlewareChain struct {
	sign        signer.Sign
	middlewares []SignMiddleware
}

func (c *MiddlewareChain) Add(m SignMiddleware) *MiddlewareChain {
	c.middlewares = append(c.middlewares, m)
	return c
}

func (c *MiddlewareChain) SignFunc() signer.Sign {
	s := c.sign
	for _, m := range c.middlewares {
		s = m(s)
	}
	return s
}
