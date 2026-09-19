// models.go
package main



// FriendInfo defines the structure for a friend, including their avatar.
// Used in the friends list and search results.
type FriendInfo struct {
	Username    string `json:"username"`
	AvatarURL   string `json:"avatarUrl,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	PhoneHash   string `json:"phoneHash,omitempty"`
}

// ConversationInfoResponse is the structure for the /conversations API response.
// It provides all necessary info for the Flutter home screen.
type ConversationInfoResponse struct {
	ConversationID int    `json:"conversationId"`
	IsGroup        bool   `json:"isGroup"`
	ChatTitle      string `json:"chatTitle"`
	CreatorUID     string `json:"creatorUid,omitempty"`
	AvatarURL      string `json:"avatarUrl,omitempty"`
	PartnerUID     string `json:"partnerUid,omitempty"` // New field
}

// --- PAYLOAD STRUCTS FOR INCOMING REQUESTS ---

// ProfilePayload is the data sent from Flutter after registration.
type ProfilePayload struct {
    PhoneNumber string `json:"phoneNumber"`
    PublicKey   string `json:"publicKey"`
	EncryptedKeyShare  string `json:"encryptedKeyShare"`
	DisplayName string `json:"displayName,omitempty"`
	Username    string `json:"username,omitempty"`  // ✅ Added for Google/Email users
}

// FriendRequestPayload is the data sent when requesting/accepting a friend.
type FriendRequestPayload struct {
	TargetUsername string `json:"targetUsername"`
}

// StartConversationPayload is the data sent when starting a new chat.
type StartConversationPayload struct {
	TargetUsername string `json:"targetUsername"`
}

// CreateGroupPayload is the data sent when creating a new group.
type CreateGroupPayload struct {
	GroupName       string   `json:"groupName"`
	Description     string   `json:"description,omitempty"`
	MemberUsernames []string `json:"memberUsernames"`
}

type UpdateKeyPayload struct {
	PublicKey string `json:"publicKey"`
}

// models.go (additions)

// PreKeyBundlePayload is the struct for the bundle of keys a client uploads
// to the `POST /keys` endpoint. Keys and signatures are sent as base64-encoded strings.
type PreKeyBundlePayload struct {
	RegistrationID    uint32              `json:"registrationId"`
	IdentityKey       string              `json:"identityKey"` // base64 encoded
	SignedPreKey      SignedPreKeyData    `json:"signedPreKey"`
	OneTimePreKeys    []OneTimePreKeyData `json:"oneTimePreKeys"`
}

// SignedPreKeyData is a nested struct within PreKeyBundlePayload.
type SignedPreKeyData struct {
	ID         int    `json:"id"`
	PublicKey  string `json:"publicKey"` // base64
	Signature  string `json:"signature"` // base64
}

// OneTimePreKeyData is also a nested struct for the list of one-time keys.
type OneTimePreKeyData struct {
	ID        int    `json:"id"`
	PublicKey string `json:"publicKey"` // base64
}


// PreKeyBundleResponse is the struct your server will send back in response
// to a `GET /keys/{userId}` request. It contains everything needed to build a session.
type PreKeyBundleResponse struct {
	RegistrationID uint32             `json:"registrationId"`
	IdentityKey    string             `json:"identityKey"`    // base64
	SignedPreKey   SignedPreKeyData   `json:"signedPreKey"`
	OneTimePreKey  *OneTimePreKeyData `json:"oneTimePreKey,omitempty"` // A single key, can be null if none are left
}

// GroupMemberInfo represents a member of a group with their role
type GroupMemberInfo struct {
	UID         string `json:"uid"`
	Username    string `json:"username"`
	AvatarURL   string `json:"avatarUrl,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Role        string `json:"role"`
	JoinedAt    string `json:"joinedAt"`
}

// GroupInfoResponse represents detailed information about a group
type GroupInfoResponse struct {
	ConversationID int               `json:"conversationId"`
	GroupName      string            `json:"groupName"`
	Description    string            `json:"description,omitempty"`
	CreatorUID     string            `json:"creatorUid"`
	AvatarURL      string            `json:"avatarUrl,omitempty"`
	CreatedAt      string            `json:"createdAt"`
	UpdatedAt      string            `json:"updatedAt"`
	Members        []GroupMemberInfo `json:"members"`
}

// AddGroupMembersPayload is the data sent when adding members to a group
type AddGroupMembersPayload struct {
	MemberUsernames []string `json:"memberUsernames"`
}

// RemoveGroupMemberPayload is the data sent when removing a member from a group
type RemoveGroupMemberPayload struct {
	MemberUID string `json:"memberUid"`
}

// ChangeGroupMemberRolePayload is the data sent when promoting/demoting a member
type ChangeGroupMemberRolePayload struct {
	MemberUID string `json:"memberUid"`
	NewRole   string `json:"newRole"` // "admin" or "member"
}

// UpdateGroupAvatarPayload is the data sent when updating group avatar
type UpdateGroupAvatarPayload struct {
	AvatarURL string `json:"avatarUrl"`
}

// UpdateGroupInfoPayload is the data sent when updating group name/description
type UpdateGroupInfoPayload struct {
	GroupName   string `json:"groupName,omitempty"`
	Description string `json:"description,omitempty"`
}
