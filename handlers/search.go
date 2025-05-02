package handlers

import (
	"fmt"
	"time"

	"github.com/bitterspread/mediax/cache"
	"github.com/bitterspread/mediax/database"
	"github.com/bitterspread/mediax/helpers"
	"github.com/bitterspread/mediax/models"
)

func GetSearchResult(query string, page int, pageSize int) ([]models.SubjectSummary, int, error) {
	db := database.GetDB()
	var subjects []models.SubjectSummary
	var total int
	likeQuery := "%" + query + "%"

	queryHash := helpers.MD5Hash(query)
	cacheKey := fmt.Sprintf("search:%s", queryHash)

	if cachedQuery, found := cache.GetCache(cacheKey); found {
		subjects := cachedQuery.([]models.SubjectSummary)
		total = len(subjects)
		return subjects, total, nil
	}

	err := db.Table("subject").
		Where("title LIKE ?", likeQuery).
		Or("alt_title LIKE ?", likeQuery).
		Order("created_at DESC").
		Find(&subjects).Error
	if err != nil {
		return nil, 0, err
	}

	cache.SetCache(cacheKey, subjects, 10*time.Minute)
	total = len(subjects)
	return subjects, total, nil
}
