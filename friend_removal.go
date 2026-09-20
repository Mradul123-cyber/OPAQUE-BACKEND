package main

import (
	"errors"
	"strings"
)

// Username is retained for existing clients. New clients use the stable UID.
type RemoveFriendPayload struct {
	TargetUID      string `json:"targetUid"`
	TargetUsername string `json:"targetUsername"`
}

var errInvalidFriendTarget = errors.New("invalid friend target")

func (p RemoveFriendPayload) resolveTarget(currentUID string, lookup func(string) (string, error)) (string, error) {
	uid := strings.TrimSpace(p.TargetUID)
	username := strings.TrimSpace(p.TargetUsername)
	if (uid == "") == (username == "") {
		return "", errInvalidFriendTarget
	}
	if uid == "" {
		var err error
		uid, err = lookup(username)
		if err != nil {
			return "", err
		}
	}
	if uid == "" || uid == currentUID {
		return "", errInvalidFriendTarget
	}
	// The handler still restricts deletion to an accepted friendship with
	// the authenticated user; supplying a UID grants no additional access.
	return uid, nil
}
