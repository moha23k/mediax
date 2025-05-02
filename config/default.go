package config

import "time"

const (
	ImageDir         = "images" // Image
	CacheControl     = 31536000 // Static files cache max-age, 1 year
	MaxCacheSubjects = 1000     // Cache
)

// API Config
var QueryLimit = 50

var DefaultConfig AppConfig
var defaultCategories = []string{"book", "movie", "tv", "anime", "game"}

func init() {
	DefaultConfig = AppConfig{
		Server: ServerConfig{
			Address:  "0.0.0.0",
			Port:     8080,
			UseHTTPS: false,
		},
		SessionTimeout: 7 * 24 * time.Hour,
		Pagination: PaginationConfig{
			PageSize: 10,
		},
		Categories: defaultCategories,
		ApiKey:     "",
	}
}

type CategoryInfo struct {
	Name        string
	Unit        string
	ActionFull  string
	ActionShort string
}

var CategoryInfoMap = map[string]CategoryInfo{
	"book": {
		Name:        "图书",
		Unit:        "本",
		ActionFull:  "阅读",
		ActionShort: "读",
	},
	"movie": {
		Name:        "电影",
		Unit:        "部",
		ActionFull:  "观看",
		ActionShort: "看",
	},
	"tv": {
		Name:        "剧集",
		Unit:        "部",
		ActionFull:  "观看",
		ActionShort: "看",
	},
	"anime": {
		Name:        "番剧",
		Unit:        "部",
		ActionFull:  "观看",
		ActionShort: "看",
	},
	"game": {
		Name:        "游戏",
		Unit:        "款",
		ActionFull:  "游玩",
		ActionShort: "玩",
	},
	"home": {
		Name: "mediaX",
	},
	"search": {
		Name: "搜索",
	},
}
