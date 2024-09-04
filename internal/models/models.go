package models

type UserToken struct {
	Login        string
	Password     string
	RefreshToken string
	AccessToken  string
}

type User struct {
	Login    string `json:"login" form:"login"`
	Password string `json:"password" form:"password"`
}

type Create_Token struct {
	Grant_type string `json:"grant_type"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	DeviceInfo string `json:"deviceInfo"`
	IsMoblie   bool   `json:"isMobile,omitempty"`
	DeviceId   string `json:"deviceId,omitempty"`
}

type Update_Token struct {
	Grant_type    string `json:"grant_type"`
	Refresh_token string `json:"refresh_token"`
}
