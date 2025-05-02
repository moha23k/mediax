package routes

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/bitterspread/mediax/config"
	"github.com/bitterspread/mediax/dataops"
	"github.com/bitterspread/mediax/helpers"
	"github.com/bitterspread/mediax/models"
)

func renderLogin(w http.ResponseWriter, data interface{}) {
	tmpl, err := template.ParseFS(tmplFS, "login.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Internal Server Error: %v", err), http.StatusInternalServerError)
		return
	}
}

func renderPage(w http.ResponseWriter, contentTemplate string, data interface{}) {
	pageTemplates, err := baseTemplates.Clone()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to clone base templates: %v", err), http.StatusInternalServerError)
		return
	}

	pageTemplates, err = pageTemplates.ParseFS(tmplFS, contentTemplate)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse templates: %v", err), http.StatusInternalServerError)
		return
	}

	// 渲染到 buffer
	buf := &bytes.Buffer{}
	if err := pageTemplates.ExecuteTemplate(buf, "baseof.html", data); err != nil {
		http.Error(w, fmt.Sprintf("failed to render page: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func handleError(w http.ResponseWriter, errorMessage, targetURL string, statusCode int) {
	data := struct {
		ErrorMessage string
		TargetPath   string
	}{
		ErrorMessage: errorMessage,
		TargetPath:   targetURL,
	}

	errorHTML, err := template.ParseFS(tmplFS, "error.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("Internal Server Error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(statusCode)
	err = errorHTML.Execute(w, data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Internal Server Error: %v", err), http.StatusInternalServerError)
		return
	}
}

func processHomeHTML(subjects []models.SubjectSummary) []models.HomeViewItem {
	var processedSubjects []models.HomeViewItem

	for _, subject := range subjects {
		imageURL := getImageURL(0, subject.HasImage, subject.SubjectType, subject.UUID, "")

		processedSubjects = append(processedSubjects, models.HomeViewItem{
			SubjectURL: fmt.Sprintf("/%s/%s", subject.SubjectType, subject.UUID),
			ImageURL:   imageURL,
		})
	}

	return processedSubjects
}

func processSingleHTML(pageTitle string, manageType int, subject models.Subject) models.SubjectView {
	imageURL := getImageURL(manageType, subject.HasImage, subject.SubjectType, subject.UUID, subject.ExternalURL)

	labels := getSubjectLabel(subject.SubjectType, subject.Status)
	statusText := labels["statusText"]
	creatorLabel := labels["creatorLabel"]
	pressLabel := labels["pressLabel"]
	pubDateLabel := labels["pubDateLabel"]
	summaryLabel := labels["summaryLabel"]

	processedSubject := models.SubjectView{
		Header:       helpers.GetHeader(subject.SubjectType),
		PageTitle:    pageTitle,
		ManageType:   manageType,
		CreatorLabel: creatorLabel,
		PressLabel:   pressLabel,
		PubDateLabel: pubDateLabel,
		StatusText:   statusText,
		SummaryLabel: summaryLabel,
		ImageURL:     imageURL,
		Subject:      subject,
	}

	if subject.Rating != 0 {
		processedSubject.RatingStar = subject.Rating * 5
	}

	if subject.ExternalURL != "" {
		processedSubject.ExternalURLIcon = getExternalURLIcon(subject.ExternalURL)
	}

	return processedSubject
}

func processCategoryHTML(subjects []models.SubjectSummary) []models.CategoryViewItem {
	var processedSubjects []models.CategoryViewItem

	for _, subject := range subjects {
		imageURL := getImageURL(0, subject.HasImage, subject.SubjectType, subject.UUID, "")

		labels := getSubjectLabel(subject.SubjectType, subject.Status)
		statusText := labels["statusText"]
		creatorLabel := labels["creatorLabel"]
		pressLabel := labels["pressLabel"]
		pubDateLabel := labels["pubDateLabel"]

		processedSubjects = append(processedSubjects, models.CategoryViewItem{
			SubjectType:  subject.SubjectType,
			SubjectURL:   fmt.Sprintf("/%s/%s", subject.SubjectType, subject.UUID),
			Title:        subject.Title,
			AltTitle:     subject.AltTitle,
			Creator:      subject.Creator,
			Press:        subject.Press,
			PubDate:      subject.PubDate,
			MarkDate:     subject.MarkDate,
			Rating:       subject.Rating,
			StatusText:   statusText,
			CreatorLabel: creatorLabel,
			PressLabel:   pressLabel,
			PubDateLabel: pubDateLabel,
			ImageURL:     imageURL,
		})
	}

	return processedSubjects
}

func processManageHTML(pageTitle string, manageType int, subject models.Subject) models.ManageView {
	imageURL := getImageURL(manageType, subject.HasImage, subject.SubjectType, subject.UUID, subject.ExternalURL)
	labels := getSubjectLabel(subject.SubjectType, subject.Status)

	var submitURL, cancelURL, buttonText, cancelText string
	var readOnlyExternal bool

	switch manageType {
	case 2: // 编辑
		submitURL = fmt.Sprintf("/%s/%s/edit", subject.SubjectType, subject.UUID)
		cancelURL = fmt.Sprintf("/%s/%s", subject.SubjectType, subject.UUID)
		buttonText = "提交修改"
		cancelText = "放弃修改"
	case 3, 4: // 新增
		submitURL = "/add/subject"
		cancelURL = "/add"
		buttonText = "确认添加"
		cancelText = "放弃添加"
	default:
		submitURL = "#"
		cancelURL = "#"
		buttonText = "提交"
		cancelText = "取消"
	}

	readOnlyExternal = (manageType == 4) || (subject.ExternalURL != "")

	return models.ManageView{
		Header:           helpers.GetHeader(subject.SubjectType),
		PageTitle:        pageTitle,
		ManageType:       manageType,
		Subject:          subject,
		CreatorLabel:     labels["creatorLabel"],
		PressLabel:       labels["pressLabel"],
		PubDateLabel:     labels["pubDateLabel"],
		SummaryLabel:     labels["summaryLabel"],
		StatusText:       labels["statusText"],
		RatingStar:       subject.Rating * 5,
		ImageURL:         imageURL,
		ExternalURLIcon:  getExternalURLIcon(subject.ExternalURL),
		SubmitURL:        submitURL,
		CancelURL:        cancelURL,
		ButtonText:       buttonText,
		CancelText:       cancelText,
		ReadOnlyExternal: readOnlyExternal,
		CategoryOptions:  getCategoryOptions(subject.SubjectType),
		StatusOptions:    getStatusOptions(subject.Status, labels["statusType"]),
		RatingOptions:    getRatingOptions(subject.Rating),
	}
}

func getCategoryOptions(selectedType string) []models.ManageCategoryOption {
	types := helpers.GetCategories()
	opts := make([]models.ManageCategoryOption, 0, len(types))
	for _, category := range types {
		opts = append(opts, models.ManageCategoryOption{
			Value:    category,
			Label:    helpers.GetSubjectTypeName(category),
			Selected: category == selectedType,
		})
	}
	return opts
}

func getStatusOptions(selected int, statusType string) []models.ManageOption {
	labels := []string{
		fmt.Sprintf("想%s", statusType),
		fmt.Sprintf("在%s", statusType),
		fmt.Sprintf("%s过", statusType),
		"搁置",
		"抛弃",
	}
	opts := make([]models.ManageOption, 0, len(labels))
	for i, label := range labels {
		opts = append(opts, models.ManageOption{
			Value:    i + 1,
			Label:    label,
			Selected: selected == i+1,
		})
	}
	return opts
}

func getRatingOptions(selected int) []models.ManageOption {
	opts := []models.ManageOption{
		{Value: 0, Label: "未评分", Selected: selected == 0},
	}
	for i := 1; i <= 10; i++ {
		opts = append(opts, models.ManageOption{
			Value:    i,
			Label:    fmt.Sprintf("%d 分", i),
			Selected: selected == i,
		})
	}
	return opts
}

func getSubjectLabel(subjectType string, status int) map[string]string {
	result := make(map[string]string)

	statusType := "看"
	creatorLabel := "导演"
	pressLabel := "制片国家/地区"
	pubDateLabel := "上映日期"
	summaryLabel := "剧情简介"

	switch subjectType {
	case "book":
		statusType = "读"
		creatorLabel = "作者"
		pressLabel = "出版社"
		pubDateLabel = "出版日期"
		summaryLabel = "内容简介"
	case "anime":
		pressLabel = "动画制作"
		pubDateLabel = "放送日期"
	case "game":
		statusType = "玩"
		creatorLabel = "开发团队"
		pressLabel = "发行公司"
		pubDateLabel = "发行日期"
		summaryLabel = "游戏简介"
	}

	var statusText string
	switch status {
	case 1:
		statusText = fmt.Sprintf("想%s", statusType)
	case 2:
		statusText = fmt.Sprintf("在%s", statusType)
	case 3:
		statusText = fmt.Sprintf("%s过", statusType)
	case 4:
		statusText = "搁置"
	case 5:
		statusText = "抛弃"
	default:
		statusText = "未知"
	}

	result["statusType"] = statusType
	result["statusText"] = statusText
	result["creatorLabel"] = creatorLabel
	result["pressLabel"] = pressLabel
	result["pubDateLabel"] = pubDateLabel
	result["summaryLabel"] = summaryLabel

	return result
}

func getExternalURLIcon(externalURL string) template.HTML {
	siteName := func(url string) string {
		switch {
		case strings.Contains(url, "douban.com"):
			return "douban"
		case strings.Contains(url, "bgm.tv"), strings.Contains(url, "bangumi.tv"):
			return "bangumi"
		default:
			return "other"
		}
	}

	site := siteName(externalURL)

	switch site {
	case "douban":
		return template.HTML(fmt.Sprintf(`<a class="subject-outlink link-douban" href="%s" target="_blank" rel="noopener noreferrer">豆瓣</a>`, externalURL))
	case "bangumi":
		return template.HTML(fmt.Sprintf(`<a class="subject-outlink link-bangumi" href="%s" target="_blank" rel="noopener noreferrer">Bangumi</a>`, externalURL))
	default:
		return template.HTML(fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>`, externalURL, externalURL))
	}
}

func getImageURL(manageType, hasImage int, subjectType, uuid, externalURL string) string {
	imgURL := "/static/default-cover.jpg"
	if hasImage == 1 {
		imgURL = fmt.Sprintf("/%s/%s/%s.jpg", config.ImageDir, subjectType, uuid)
	}
	if manageType == 4 {
		imageName, err := dataops.PreDownloadImageName(externalURL)
		if err == nil {
			imgURL = fmt.Sprintf("/%s/temp/%s", config.ImageDir, imageName)
		}
	}
	return imgURL
}

func generatePageNumbers(current, total int) []int {
	if total <= 1 {
		return nil
	}

	var pages []int
	start := current - 2
	if start < 1 {
		start = 1
	}
	end := start + 4
	if end > total {
		end = total
		start = end - 4
		if start < 1 {
			start = 1
		}
	}
	for i := start; i <= end; i++ {
		pages = append(pages, i)
	}

	return pages
}
