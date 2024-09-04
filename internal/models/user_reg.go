package models

type UserRegistration struct {
	Email                string     `json:"email" form:"email"`
	Password             string     `json:"password" form:"password"`
	FirstName            string     `json:"firstName" form:"firstName"`
	MiddleName           string     `json:"middleName" form:"middleName"`
	LastName             string     `json:"lastName" form:"lastName"`
	PhoneNumber          string     `json:"phoneNumber" form:"phoneNumber"`
	TradePointName       string     `json:"tradePointName" form:"tradePointName"`
	NotificationsEnabled bool       `json:"notificationsEnabled" form:"notificationsEnabled"`
	ProjectId            *int       `json:"projectId" form:"projectId"`
	RegFields            []RegField `json:"regFields,omitempty" form:"regFields,omitempty"`
}

type RegField struct {
	FieldToAnswer string `json:"fieldToAnswer"`
	FieldValue    string `json:"fieldValue"`
}

type TradePoint struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type ConfirmEmailRequest struct {
	NewEmail string `json:"newEmail"`
}

type ConfirmCodeRequest struct {
	Code string `json:"code"`
}
