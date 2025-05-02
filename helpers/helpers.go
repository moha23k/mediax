package helpers

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/bitterspread/mediax/config"
	"github.com/bitterspread/mediax/models"
)

func GenerateUUID() string {
	return uuid.New().String()
}

func GetTimestamp() int64 {
	return time.Now().Unix()
}

func StringToInt(value string) (int, error) {
	result, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return result, nil
}

func MD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return fmt.Sprintf("%x", hash)
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GetHeader(currentCategory string) models.Header {
	var options []models.HeaderOption
	for _, cat := range GetCategories() {
		options = append(options, models.HeaderOption{
			Category:     cat,
			CategoryName: GetSubjectTypeName(cat),
		})
	}

	return models.Header{
		Options:     options,
		User:        config.App.User.Username,
		Current:     currentCategory,
		CurrentName: GetSubjectTypeName(currentCategory),
	}
}

func GetCategories() []string {
	return append([]string{}, config.App.Categories...)
}

func GetSubjectTypeName(subjectType string) string {
	if info, ok := config.CategoryInfoMap[subjectType]; ok {
		return info.Name
	}
	return "未知"
}

func GetSubjectActionName(subjectType string) (string, string) {
	if info, ok := config.CategoryInfoMap[subjectType]; ok {
		return info.ActionFull, info.ActionShort
	}
	return "", ""
}

func GetSubjectUnitName(subjectType string) string {
	if info, ok := config.CategoryInfoMap[subjectType]; ok {
		return info.Unit
	}
	return ""
}

func GetCategoryIcon(category, width, fill string) string {
	switch category {
	case "book":
		return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="%s" fill="%s"><path d="M23 5v13.883l-1 .117v-16c-3.895.119-7.505.762-10.002 2.316-2.496-1.554-6.102-2.197-9.998-2.316v16l-1-.117v-13.883h-1v15h9.057c1.479 0 1.641 1 2.941 1 1.304 0 1.461-1 2.942-1h9.06v-15h-1zm-12 13.645c-1.946-.772-4.137-1.269-7-1.484v-12.051c2.352.197 4.996.675 7 1.922v11.613zm9-1.484c-2.863.215-5.054.712-7 1.484v-11.613c2.004-1.247 4.648-1.725 7-1.922v12.051z"/></svg>`, width, fill)
	case "movie":
		return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="%s" fill="%s"><path d="M13.112 6L16 2.625 15.219 2 12 5.75 8.781 2 8 2.625 10.888 6H0v16h24V6H13.112zM21 20H3V8h18v12zM9 18v-8l7 4-7 4z"/></svg>`, width, fill)
	case "tv":
		return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="%s" fill="%s"><path d="M13.112 6L16 2.625 15.219 2 12 5.75 8.781 2 8 2.625 10.888 6H0v16h24V6H13.112zM21 20H3V8h18v12zM6.164 11h5.673v1.418h-2.01V17H8.174v-4.582h-2.01V11zm9.961 0l-1.158 3.653L13.816 11h-1.701l1.942 6h1.792l1.986-6h-1.71z"/></svg>`, width, fill)
	case "anime":
		return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="%s" fill="%s"><path d="M13.112 6L16 2.625 15.219 2 12 5.75 8.781 2 8 2.625 10.888 6H0v16h24V6H13.112zM21 20H3V8h18v12zM8 11.5a1.8 1.8 0 1 0 0 3.6 1.8 1.8 0 0 0 0-3.6zm8 0a1.8 1.8 0 1 0 0 3.6 1.8 1.8 0 0 0 0-3.6z"/></svg>`, width, fill)
	case "game":
		return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="%s" fill="%s"><path d="M17.622 3c-1.913 0-2.558 1.382-5.623 1.382C8.99 4.382 8.253 3 6.376 3 1.167 3 0 13.375 0 17.348 0 19.493.817 21 2.469 21c3.458 0 2.926-5 6.915-5h5.23c3.989 0 3.457 5 6.915 5C23.181 21 24 19.494 24 17.349 24 13.376 22.831 3 17.622 3zM7 13a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm10-6a1 1 0 1 1 0 2 1 1 0 0 1 0-2zm-2 4a1 1 0 1 1 0-2 1 1 0 0 1 0 2zm2 2a1 1 0 1 1 0-2 1 1 0 0 1 0 2zm2-2a1 1 0 1 1 0-2 1 1 0 0 1 0 2zM8.75 10c0 .965-.785 1.75-1.75 1.75S5.25 10.965 5.25 10 6.035 8.25 7 8.25s1.75.785 1.75 1.75z"/></svg>`, width, fill)
	default:
		return ""
	}
}
