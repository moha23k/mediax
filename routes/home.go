package routes

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/bitterspread/mediax/handlers"
	"github.com/bitterspread/mediax/helpers"
	"github.com/bitterspread/mediax/models"
)

func redirectToHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}
}

func handleHomePage(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	weekdays := [...]string{"星期日", "星期一", "星期二", "星期三", "星期四", "星期五", "星期六"}
	today := fmt.Sprintf("%d月%d日 %s", now.Month(), now.Day(), weekdays[now.Weekday()])

	recentSubjects, err := handlers.GetRecentSubjects(5)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get recent subjects: %v", err), http.StatusInternalServerError)
		return
	}

	var recentGroups []models.HomeViewType
	subjectTypes := helpers.GetCategories()
	for _, subjectType := range subjectTypes {
		subjectActionFullName, subjectActionShortName := helpers.GetSubjectActionName(subjectType)
		summary, _ := handlers.GetHomeSummary(subjectType)
		recentGroups = append(recentGroups, models.HomeViewType{
			SubjectType:            subjectType,
			SubjectTypeName:        helpers.GetSubjectTypeName(subjectType),
			SubjectActionFullName:  subjectActionFullName,
			SubjectActionShortName: subjectActionShortName,
			SubjectUnitName:        helpers.GetSubjectUnitName(subjectType),
			CategoryIcon:           template.HTML(helpers.GetCategoryIcon(subjectType, "30", fmt.Sprintf("var(--%s-color)", subjectType))),
			Items:                  processHomeHTML(recentSubjects[subjectType]),
			Summary:                summary,
		})
	}

	data := models.HomeView{
		Header:       helpers.GetHeader("home"),
		Today:        today,
		PageTitle:    "主页",
		RecentGroups: recentGroups,
	}

	renderPage(w, "index.html", data)
}
