package domain

import "errors"

var (
	ErrThreatNotFound      = errors.New("threat not found")
	ErrThreatAlreadyExists = errors.New("threat already exists")
	ErrInvalidMD5          = errors.New("invalid md5")
	ErrInvalidName         = errors.New("invalid threat name")
	ErrInvalidSeverity     = errors.New("invalid threat severity")
)
