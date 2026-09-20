package main

import (
	"database/sql"
	"encoding/json"
	"testing"
)

func TestRemoveFriendTarget(t *testing.T) {
	cases := []struct {
		name, body, want string
		wantErr          error
		lookups          int
	}{
		{"UID skips username lookup", `{"targetUid":"friend-uid"}`, "friend-uid", nil, 0},
		{"old client username", `{"targetUsername":"alice"}`, "friend-uid", nil, 1},
		{"missing", `{}`, "", errInvalidFriendTarget, 0},
		{"blank", `{"targetUid":"  "}`, "", errInvalidFriendTarget, 0},
		{"ambiguous", `{"targetUid":"friend-uid","targetUsername":"alice"}`, "", errInvalidFriendTarget, 0},
		{"self UID", `{"targetUid":"me"}`, "", errInvalidFriendTarget, 0},
		{"self username", `{"targetUsername":"myself"}`, "", errInvalidFriendTarget, 1},
		{"unknown username", `{"targetUsername":"missing"}`, "", sql.ErrNoRows, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p RemoveFriendPayload
			if err := json.Unmarshal([]byte(tc.body), &p); err != nil {
				t.Fatal(err)
			}
			calls := 0
			uid, err := p.resolveTarget("me", func(name string) (string, error) {
				calls++
				if name == "myself" {
					return "me", nil
				}
				if name == "missing" {
					return "", sql.ErrNoRows
				}
				return "friend-uid", nil
			})
			if uid != tc.want || err != tc.wantErr || calls != tc.lookups {
				t.Fatalf("got (%q, %v), lookups=%d; want (%q, %v), lookups=%d", uid, err, calls, tc.want, tc.wantErr, tc.lookups)
			}
		})
	}
}
