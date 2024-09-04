package models

type Response_Error struct {
	Error string `json:"Error"`
}

type Response_OK struct {
	Status string `json:"Status"`
}

type Response struct {
	Status  int         `json:"Status"`
	Payload interface{} `json:"Payload"`
}
