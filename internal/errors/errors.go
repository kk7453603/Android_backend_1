package customerrors

import (
	"errors"
	"net/http"
)

var (
	ErrUserExists         = errors.New("user already exists")
	ErrTokenExpired       = errors.New("token is expired")
	ErrTokensMatch        = errors.New("tokens doesn't match")
	ErrRefreshToken       = errors.New("wrong refresh token")
	ErrAccessToken        = errors.New("wrong access token")
	ErrPasswordFormat     = errors.New("wrong password format")
	ErrEmailNotFound      = errors.New("email not found")
	ErrEmailExists        = errors.New("email already exists")
	ErrEmailInvalid       = errors.New("invalid email address")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAddError       = errors.New("user add error")
)

const (
	EXPECTED   = "expected"
	UNEXPECTED = "unexpected"
	WARNING    = "warning"
	FATAL      = "fatal"
)

type ExportableError struct {
	Code       string `json:"error_code"`
	HttpStatus int    `json:"http_status"`
	Severity   string `json:"severity"`
	Message    string `json:"message,omitempty"`
}

func (e *ExportableError) WithMessage(message string) *ExportableError {
	errorWithMessage := *e
	errorWithMessage.Message = message
	return &errorWithMessage
}

func (e *ExportableError) Default() *ExportableError {
	return e.WithMessage(e.Message)
}

var ErrInvalidTokenType = ExportableError{
	Code:       "4011",
	HttpStatus: http.StatusUnauthorized,
	Severity:   UNEXPECTED,
}

var ErrInvalidToken = ExportableError{
	Code:       "4012",
	HttpStatus: http.StatusUnauthorized,
	Severity:   FATAL,
}

var ErrMissingAuthToken = ExportableError{
	Code:       "4013",
	HttpStatus: http.StatusUnauthorized,
	Severity:   UNEXPECTED,
}

var ErrInvalidOrExpiredToken = ExportableError{
	Code:       "4014",
	HttpStatus: http.StatusUnauthorized,
	Severity:   UNEXPECTED,
}

var ErrMissingSecureToken = ExportableError{
	Code:       "4015",
	HttpStatus: http.StatusUnauthorized,
	Severity:   FATAL,
	Message:    "missing secure token",
}

var ErrBadRequestMissingIDParam = ExportableError{
	Code:       "4004",
	HttpStatus: http.StatusBadRequest,
	Severity:   EXPECTED,
	Message:    "the id path param is required, but not provided",
}

var ErrBadRequestMissingCountryParam = ExportableError{
	Code:       "4005",
	HttpStatus: http.StatusBadRequest,
	Severity:   EXPECTED,
	Message:    "the country path param is required, but not provided",
}

var ErrBadRequestParseBody = ExportableError{
	Code:       "4006",
	HttpStatus: http.StatusBadRequest,
	Severity:   EXPECTED,
}

var ErrBadRequestPhotosLimitReached = ExportableError{
	Code:       "4007",
	HttpStatus: http.StatusBadRequest,
	Severity:   EXPECTED,
	Message:    "The maximum number of photos is 10",
}

var ErrBadRequestChatWithYourself = ExportableError{
	Code:       "4008",
	HttpStatus: http.StatusBadRequest,
	Severity:   UNEXPECTED,
	Message:    "You can't create chat with yourself",
}

var ErrUserIsBlocked = ExportableError{
	Code:       "4230",
	HttpStatus: http.StatusLocked,
	Severity:   EXPECTED,
}

var ErrUserIsDeleted = ExportableError{
	Code:       "4231",
	HttpStatus: http.StatusLocked,
	Severity:   EXPECTED,
}

var ErrUserAlreadyExists = ExportableError{
	Code:       "4232",
	HttpStatus: http.StatusLocked,
	Severity:   EXPECTED,
}

var ErrUserPasswordFormat = ExportableError{
	Code:       "4233",
	HttpStatus: http.StatusLocked,
	Severity:   EXPECTED,
	Message:    "Password format error",
}

var ErrDeviceIsDeprecated = ExportableError{
	Code:       "4234",
	HttpStatus: http.StatusLocked,
	Severity:   EXPECTED,
}

var ErrUserEmailNotFound = ExportableError{
	Code:       "4235",
	HttpStatus: http.StatusLocked,
	Severity:   EXPECTED,
	Message:    ErrEmailNotFound.Error(),
}

var ErrUserEmailExists = ExportableError{
	Code:       "4236",
	HttpStatus: http.StatusLocked,
	Severity:   EXPECTED,
	Message:    ErrEmailExists.Error(),
}

var ErrUserEmailInvalid = ExportableError{
	Code:       "4237",
	HttpStatus: http.StatusLocked,
	Severity:   EXPECTED,
	Message:    ErrEmailInvalid.Error(),
}

var ErrInternalServerError = ExportableError{
	Code:       "5000",
	HttpStatus: http.StatusInternalServerError,
	Severity:   FATAL,
}

var ErrInternalServerErrorProfileService = ExportableError{
	Code:       "5001",
	HttpStatus: http.StatusInternalServerError,
	Severity:   FATAL,
}

var ErrInternalServerErrorDatabaseFailed = ExportableError{
	Code:       "5003",
	HttpStatus: http.StatusInternalServerError,
	Severity:   FATAL,
}

var ErrInternalServerErrorJWTCreateError = ExportableError{
	Code:       "5004",
	HttpStatus: http.StatusInternalServerError,
	Severity:   FATAL,
}

var ErrDBUserAddError = ExportableError{
	Code:       "6000",
	HttpStatus: http.StatusInternalServerError,
	Severity:   FATAL,
}
