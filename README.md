Session Role Manager [![Build Status](https://travis-ci.org/casbin/session-role-manager.svg?branch=master)](https://travis-ci.org/casbin/session-role-manager) [![Coverage Status](https://coveralls.io/repos/github/casbin/session-role-manager/badge.svg?branch=master)](https://coveralls.io/github/casbin/session-role-manager?branch=master) [![Godoc](https://godoc.org/github.com/casbin/session-role-manager?status.svg)](https://godoc.org/github.com/casbin/session-role-manager)
====

Session Role Manager is the [Session-based](https://en.wikipedia.org/wiki/Session_(computer_science)) role manager for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load session-based role hierarchy (user-role mapping) from Casbin policy or save role hierarchy to it. The session is only active in the specified time range.

## Installation

    go get github.com/casbin/session-role-manager

## Simple Example

```go
package main

import (
	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	sessionrolemanager "github.com/casbin/session-role-manager"
)

func main() {
	// NewEnforcer(modelPath, policyPath) automatically uses the default
	// role manager when loading policy. So if we want to use a custom
	// role manager, and this role manager relies on Casbin policy,
	// we should manually set the role manager before loading policy.
	e, err := casbin.NewEnforcer("examples/rbac_model_with_sessions.conf")
	if err != nil {
		panic(err)
	}

	// Manually set an adapter.
	a := fileadapter.NewAdapter("examples/rbac_policy_with_sessions.csv")
	e.SetAdapter(a)

	// Use our role manager.
	rm := sessionrolemanager.NewRoleManager(10)
	e.SetRoleManager(rm)

	// If our role manager relies on Casbin policy (like reading "g"
	// policy rules), then we have to set the role manager before loading
	// policy.
	//
	// Otherwise, we can set the role manager at any time, because role
	// manager has nothing to do with the adapter.
	e.LoadPolicy()

	// Check the permission.
	// the 4th arg is the querying time in UNIX time format.
	e.Enforce("alice", "data1", "read", "1508503308708987131")
}
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
