package models

import "html/template"

// Header
type HeaderOption struct {
	Category     string
	CategoryName string
}

type Header struct {
	Options     []HeaderOption
	User        string
	Current     string
	CurrentName string
}

// Home Page
type HomeLastItem struct {
	Title      string
	SubjectURL string
	Status     int
	Date       string
}

type HomeSummary struct {
	MonthCount    int
	HalfYearCount int
	YearCount     int
	LastItem      HomeLastItem
}

type HomeViewItem struct {
	SubjectURL string
	ImageURL   string
}

type HomeViewType struct {
	SubjectType            string
	SubjectTypeName        string
	SubjectActionFullName  string
	SubjectActionShortName string
	SubjectUnitName        string
	CategoryIcon           template.HTML
	Items                  []HomeViewItem
	Summary                HomeSummary
}

type HomeView struct {
	Header       Header
	Today        string
	PageTitle    string
	RecentGroups []HomeViewType
}

// Category Page
type CategoryViewItem struct {
	SubjectType  string
	SubjectURL   string
	Title        string
	AltTitle     string
	Creator      string
	Press        string
	PubDate      string
	MarkDate     string
	Rating       int
	StatusText   string
	CreatorLabel string
	PressLabel   string
	PubDateLabel string
	ImageURL     string
}

type StatusCounts struct {
	All     int64
	Todo    int64
	Doing   int64
	Done    int64
	OnHold  int64
	Dropped int64
}

type StatusLabel struct {
	Value int
	Label string
	Count int64
}

type CategoryView struct {
	Header       Header
	PageTitle    string
	CategoryIcon template.HTML
	Status       int
	TotalCounts  int64
	StatusList   []StatusLabel
	SortBy       int
	CurrentPage  int
	TotalPages   int
	PageNumbers  []int
	PageParams   template.URL
	Subjects     []CategoryViewItem
}

type SubjectSummary struct {
	UUID        string
	SubjectType string
	Title       string
	AltTitle    string
	Creator     string
	Press       string
	Status      int
	Rating      int
	HasImage    int
	PubDate     string
	MarkDate    string
}

// Subject Page
type SubjectView struct {
	Header          Header
	PageTitle       string
	ManageType      int
	CreatorLabel    string
	PressLabel      string
	PubDateLabel    string
	SummaryLabel    string
	StatusText      string
	RatingStar      int
	ImageURL        string
	ExternalURLIcon template.HTML
	Subject         Subject
}

// Search Page
type SearchView struct {
	Header      Header
	PageTitle   string
	Query       string
	QueryType   string
	TotalCount  int
	CurrentPage int
	TotalPages  int
	PageNumbers []int
	PageParams  template.URL
	Subjects    []CategoryViewItem
}

// Manage Page
// ManageType - 1: 显示, 2: 编辑, 3: 新增(手动), 4: 新增(自动)
type AddView struct {
	Header    Header
	PageTitle string
}

type ManageCategoryOption struct {
	Value    string
	Label    string
	Selected bool
}

type ManageOption struct {
	Value    int
	Label    string
	Selected bool
}

type ManageView struct {
	Header           Header
	PageTitle        string
	ManageType       int
	Subject          Subject
	CreatorLabel     string
	PressLabel       string
	PubDateLabel     string
	SummaryLabel     string
	StatusText       string
	RatingStar       int
	ImageURL         string
	ExternalURLIcon  template.HTML
	SubmitURL        string
	CancelURL        string
	ButtonText       string
	CancelText       string
	ReadOnlyExternal bool
	CategoryOptions  []ManageCategoryOption
	StatusOptions    []ManageOption
	RatingOptions    []ManageOption
}
