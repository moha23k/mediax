package handlers

import (
	"fmt"

	"github.com/bitterspread/mediax/cache"
	"github.com/bitterspread/mediax/database"
	"github.com/bitterspread/mediax/models"
)

func GetSubjectsByType(subjectType string, status, page, pageSize, sortBy int) ([]models.SubjectSummary, error) {
	db := database.GetDB()
	var subjects []models.SubjectSummary

	cachePageKey := fmt.Sprintf("page:%s:%d:%d", subjectType, status, sortBy)

	if page == 1 {
		if cachedSubjects, found := cache.GetCache(cachePageKey); found {
			subjects = cachedSubjects.([]models.SubjectSummary)
			return subjects, nil
		}
	}

	// 索引顺序 subject_type > mark_date/id > status
	query := db.
		Table("subject").
		Where("subject_type = ?", subjectType)

	switch sortBy {
	case 2:
		query = query.Order("mark_date DESC")
	case 3:
		query = query.Order("id ASC")
	case 4:
		query = query.Order("mark_date ASC")
	default:
		query = query.Order("id DESC")
	}

	if status > 0 {
		query = query.Where("status = ?", status)
	}

	query = query.Offset((page - 1) * pageSize).Limit(pageSize)

	err := query.Find(&subjects).Error
	if err != nil {
		return nil, err
	}

	if page == 1 {
		cache.SetCache(cachePageKey, subjects)
	}

	return subjects, nil
}

func GetStatusCounts(subjectType string) (models.StatusCounts, error) {
	db := database.GetDB()
	var counts models.StatusCounts

	cacheKey := fmt.Sprintf("count:%s", subjectType)
	if cachedCounts, found := cache.GetCache(cacheKey); found {
		return cachedCounts.(models.StatusCounts), nil
	}

	rows, err := db.Table("subject").
		Select("status, COUNT(*) as count").
		Where("subject_type = ?", subjectType).
		Group("status").
		Rows()
	if err != nil {
		return counts, err
	}
	defer rows.Close()

	for rows.Next() {
		var status int
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return counts, err
		}
		switch status {
		case 1:
			counts.Todo = count
		case 2:
			counts.Doing = count
		case 3:
			counts.Done = count
		case 4:
			counts.OnHold = count
		case 5:
			counts.Dropped = count
		}
	}

	counts.All = counts.Todo + counts.Doing + counts.Done + counts.OnHold + counts.Dropped

	cache.SetCache(cacheKey, counts)

	return counts, nil
}
