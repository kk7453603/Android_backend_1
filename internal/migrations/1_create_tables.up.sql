CREATE TABLE users (
	Id serial PRIMARY KEY,
	username varchar(100),
	passwd varchar(255),
	refresh_token varchar(255),
	access_token varchar(255)
)