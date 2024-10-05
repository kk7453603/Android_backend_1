package models

type UserRegistration struct {
	Password string `json:"password" form:"password"`
	Nickname string `json:"nickname" form:"nickname"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}
