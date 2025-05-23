package dataops

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bitterspread/mediax/database"
	"github.com/bitterspread/mediax/models"
)

func ExportToJSONAPI(subjectType string, limit, offset, sortBy int) ([]byte, error) {
	db := database.GetDB()

	var subjects []models.SubjectExportItem
	query := db.Model(&models.Subject{}).
		Select("uuid, subject_type, title, alt_title, pub_date, creator, press, status, rating, summary, comment, external_url, mark_date, created_at").
		Offset(offset)

	if subjectType != "all" {
		query = query.Where("subject_type = ?", subjectType)
	}

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

	query = query.Limit(limit)

	if err := query.Find(&subjects).Error; err != nil {
		return nil, fmt.Errorf("failed to query subjects: %v", err)
	}

	totalCount := len(subjects)
	if totalCount == 0 {
		message := map[string]string{
			"message": "no records found",
		}
		jsonData, err := json.Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal json: %v", err)
		}
		return jsonData, nil
	}

	exportData := models.SubjectExportAPI{
		Subjects:     subjects,
		ResponseTime: time.Now().Format(time.RFC3339),
		TotalCount:   totalCount,
		Limit:        limit,
		Offset:       offset,
	}

	jsonData, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %v", err)
	}

	return jsonData, nil
}
