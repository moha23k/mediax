package routes

import (
	"fmt"
	"html/template"
	"math"
	"net/http"
	"strings"

	"github.com/bitterspread/mediax/config"
	"github.com/bitterspread/mediax/handlers"
	"github.com/bitterspread/mediax/helpers"
	"github.com/bitterspread/mediax/models"
)

func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(query) < 4 || len(query) > 32 {
		errorMessage := "search keyword must be between 4 and 32 characters (2 至 16 个汉字)"
		handleError(w, errorMessage, "home", 302)
		return
	}

	validType := map[string]bool{
		"all":   true,
		"book":  true,
		"movie": true,
		"tv":    true,
		"anime": true,
		"game":  true,
	}
	subjectType := r.URL.Query().Get("subject_type")
	if !validType[subjectType] {
		handleError(w, "Invalid subject type", "home", 400)
		return
	}

	pageSize := config.App.Pagination.PageSize
	page, err := helpers.StringToInt(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	subjects, total, err := handlers.GetSearchResult(query, page, pageSize)
	if err != nil {
		handleError(w, fmt.Sprint(err), "add", 500)
		return
	}

	if subjectType != "all" {
		var filtered []models.SubjectSummary
		for _, subject := range subjects {
			if subject.SubjectType == subjectType {
				filtered = append(filtered, subject)
			}
		}
		subjects = filtered
		total = len(subjects)
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	pagedSubjects := subjects[start:end]

	totalPages := int(math.Ceil(float64(total) / float64(pageSize)))
	pageParams := fmt.Sprintf("&q=%s&subject_type=%s", query, subjectType)

	data := models.SearchView{
		Header:      helpers.GetHeader("search"),
		PageTitle:   "搜索结果 " + query,
		Query:       query,
		QueryType:   subjectType,
		TotalCount:  total,
		CurrentPage: page,
		TotalPages:  totalPages,
		PageNumbers: generatePageNumbers(page, totalPages),
		PageParams:  template.URL(pageParams),
		Subjects:    processCategoryHTML(pagedSubjects),
	}

	renderPage(w, "search.html", data)
}
