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

func handleCategory(w http.ResponseWriter, r *http.Request) {
	category := strings.TrimPrefix(r.URL.Path, "/")

	pageSize := config.App.Pagination.PageSize
	page, err := helpers.StringToInt(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	// Status - 1: 想看, 2: 在看, 3: 已看 (4: 搁置, 5: 抛弃)
	status, err := helpers.StringToInt(r.URL.Query().Get("status"))
	if err != nil || status < 0 || status > 5 {
		status = 0
	}

	// sortBy - 1: 最近添加, 2: 最近标记, 3: 最早添加, 4: 最早标记
	sortBy, err := helpers.StringToInt(r.URL.Query().Get("sort_by"))
	if err != nil || sortBy < 1 || sortBy > 4 {
		sortBy = 1
	}

	statusCounts, err := handlers.GetStatusCounts(category)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to calculate totals for %s: %v", category, err)
		handleError(w, errorMessage, "home", 500)
		return
	}

	var totalPages int
	getTotalPages := func(count int64) int {
		return int(math.Ceil(float64(count) / float64(pageSize)))
	}
	switch status {
	case 0:
		totalPages = getTotalPages(statusCounts.All)
	case 1:
		totalPages = getTotalPages(statusCounts.Todo)
	case 2:
		totalPages = getTotalPages(statusCounts.Doing)
	case 3:
		totalPages = getTotalPages(statusCounts.Done)
	case 4:
		totalPages = getTotalPages(statusCounts.OnHold)
	case 5:
		totalPages = getTotalPages(statusCounts.Dropped)
	}
	if page > totalPages {
		page = 1
	}

	subjects, err := handlers.GetSubjectsByType(category, status, page, pageSize, sortBy)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get %s list: %v", category, err)
		handleError(w, errorMessage, "home", 500)
		return
	}

	_, subjectActionShortName := helpers.GetSubjectActionName(category)

	statusList := []models.StatusLabel{
		{Value: 1, Label: fmt.Sprintf("想%s", subjectActionShortName), Count: statusCounts.Todo},
		{Value: 2, Label: fmt.Sprintf("在%s", subjectActionShortName), Count: statusCounts.Doing},
		{Value: 3, Label: fmt.Sprintf("%s过", subjectActionShortName), Count: statusCounts.Done},
		{Value: 4, Label: "搁置", Count: statusCounts.OnHold},
		{Value: 5, Label: "抛弃", Count: statusCounts.Dropped},
	}

	var pageParams string
	if status != 0 {
		pageParams += fmt.Sprintf("&status=%d", status)
	}
	if sortBy != 1 {
		pageParams += fmt.Sprintf("&sort_by=%d", sortBy)
	}

	data := models.CategoryView{
		Header:       helpers.GetHeader(category),
		PageTitle:    helpers.GetSubjectTypeName(category),
		CategoryIcon: template.HTML(helpers.GetCategoryIcon(category, "28", "currentColor")),
		Status:       status,
		TotalCounts:  statusCounts.All,
		StatusList:   statusList,
		SortBy:       sortBy,
		CurrentPage:  page,
		TotalPages:   totalPages,
		PageNumbers:  generatePageNumbers(page, totalPages),
		PageParams:   template.URL(pageParams),
		Subjects:     processCategoryHTML(subjects),
	}

	renderPage(w, "category.html", data)
}
