package models

type User struct {
	Login        string `json:"login"`
	Password     string `json:"password"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (u *RegUser) ForDomain() *User {
	return &User{
		Login:    u.Login,
		Password: u.Password,
	}
}

type RegUser struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type ResponseError struct {
	Error string `json:"error"`
}

type ResponseOK struct {
	Status string `json:"status"`
}

type UserToken struct {
	Login        string `json:"login"`
	Password     string `json:"password,omitempty"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}
