package handlers

import (
	"errors"
	"fmt"
	"time"

	"github.com/bitterspread/mediax/cache"
	"github.com/bitterspread/mediax/database"
	"github.com/bitterspread/mediax/helpers"
	"github.com/bitterspread/mediax/models"
	"gorm.io/gorm"
)

func GetRecentSubjects(limit int) (map[string][]models.SubjectSummary, error) {
	db := database.GetDB()
	results := make(map[string][]models.SubjectSummary)
	subjectTypes := helpers.GetCategories()

	for _, subjectType := range subjectTypes {
		cacheKey := fmt.Sprintf("home:%s", subjectType)
		if cachedValue, found := cache.GetCache(cacheKey); found {
			results[subjectType] = cachedValue.([]models.SubjectSummary)
			continue
		}

		var subjects []models.SubjectSummary
		err := db.Model(&models.Subject{}).
			Select("uuid, subject_type, title, status, has_image").
			Where("subject_type = ?", subjectType).
			Order("id desc").
			Limit(limit).
			Find(&subjects).Error
		if err != nil {
			return nil, err
		}
		results[subjectType] = subjects
		cache.SetCache(cacheKey, subjects)
	}

	return results, nil
}

func GetHomeSummary(subjectType string) (models.HomeSummary, error) {
	db := database.GetDB()

	cacheKey := fmt.Sprintf("home_summary:%s", subjectType)
	if cachedValue, found := cache.GetCache(cacheKey); found {
		return cachedValue.(models.HomeSummary), nil
	}

	now := time.Now()
	var monthCount, halfYearCount, yearCount int
	var lastItem models.HomeLastItem

	var lastSubject models.SubjectSummary
	err := db.Model(&models.Subject{}).
		Where("subject_type = ? AND status IN (2, 3) AND mark_date IS NOT NULL AND mark_date != ''", subjectType).
		Order("mark_date desc").
		Limit(1).
		Select("uuid, subject_type, title, mark_date, status").
		First(&lastSubject).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return models.HomeSummary{}, err
	}

	var subjects []models.SubjectSummary
	err = db.Model(&models.Subject{}).
		Where("subject_type = ? AND status = 3 AND mark_date IS NOT NULL AND mark_date != ''", subjectType).
		Order("mark_date desc").
		Find(&subjects).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return models.HomeSummary{}, err
	}

	for _, subject := range subjects {
		markDate, err := time.Parse("2006-01-02", subject.MarkDate)
		if err != nil {
			continue
		}

		diff := now.Sub(markDate)
		if diff.Hours() <= 24*30 {
			monthCount++
		}
		if diff.Hours() <= 24*30*6 {
			halfYearCount++
		}
		if diff.Hours() <= 24*365 {
			yearCount++
		}
	}

	if lastSubject.MarkDate != "" {
		markDate, err := time.Parse("2006-01-02", lastSubject.MarkDate)
		if err == nil {
			lastItem = models.HomeLastItem{
				Title:      lastSubject.Title,
				SubjectURL: fmt.Sprintf("/%s/%s", lastSubject.SubjectType, lastSubject.UUID),
				Status:     lastSubject.Status,
				Date:       markDate.Format("2006-01-02"),
			}
		}
	}

	result := models.HomeSummary{
		MonthCount:    monthCount,
		HalfYearCount: halfYearCount,
		YearCount:     yearCount,
		LastItem:      lastItem,
	}

	cache.SetCache(cacheKey, result)

	return result, nil
}
