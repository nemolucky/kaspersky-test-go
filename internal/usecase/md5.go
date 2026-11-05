package usecase

import (
	"regexp"
	"strings"

	"github.com/nemolucky/kaspersky-test-go/internal/domain"
)

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func ParseMD5(md5 string) (string, error) {

	if !md5Pattern.MatchString(md5) {
		return "", domain.ErrInvalidMD5
	}

	return strings.ToLower(md5), nil
}
