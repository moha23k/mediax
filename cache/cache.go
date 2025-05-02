package cache

import (
	"container/list"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bitterspread/mediax/config"
)

// 首页缓存: home:{subject_type}
// 首页总结缓存: home_summary:{subject_type}
// 分类首页缓存: page:{subject_type}:{status}:{sort_by}
// 分类总数缓存: count:{subject_type}
// 条目缓存: subject:{uuid}
// 搜索缓存: search:{query_key}:{page}
// 搜索总数缓存: count:search:{query_key}
type CacheItem struct {
	Value      interface{}
	Expiration time.Time
}

var (
	cacheItem         sync.Map
	cacheSubjectOrder = list.New() // FIFO list for subject cache
	cacheSubjectIndex sync.Map
)

// 获取缓存项
func GetCache(key string) (interface{}, bool) {
	if value, found := cacheItem.Load(key); found {
		item := value.(CacheItem)
		if time.Now().After(item.Expiration) {
			cacheItem.Delete(key)
			return nil, false
		}
		// fmt.Printf("已获得缓存: %s\n", key)
		return item.Value, true
	}

	return nil, false
}

// 设置缓存项
func SetCache(key string, value interface{}, duration ...time.Duration) {
	var expiration time.Time
	if len(duration) > 0 {
		expiration = time.Now().Add(duration[0])
	} else {
		expiration = time.Now().Add(10 * 365 * 24 * time.Hour) // 默认 10 年
	}

	if strings.HasPrefix(key, "subject:") {
		if countSubjectCache() >= config.MaxCacheSubjects {
			deleteOldestSubjectCache()
		}

		if elem, ok := cacheSubjectIndex.Load(key); ok {
			cacheSubjectOrder.Remove(elem.(*list.Element))
		}
		elem := cacheSubjectOrder.PushBack(key)
		cacheSubjectIndex.Store(key, elem)
	}

	item := CacheItem{
		Value:      value,
		Expiration: expiration,
	}
	cacheItem.Store(key, item)
	// fmt.Printf("已设置缓存: %s\n", key)
}

// 删除缓存项
func DeleteCache(key string) {
	cacheItem.Delete(key)

	if strings.HasPrefix(key, "subject:") {
		if elem, ok := cacheSubjectIndex.Load(key); ok {
			cacheSubjectOrder.Remove(elem.(*list.Element))
			cacheSubjectIndex.Delete(key)
		}
	}
	// fmt.Printf("已删除缓存: %s\n", key)
}

// 清理通用缓存
func ClearCommonCache(subjectType string) {
	homeCacheKey := fmt.Sprintf("home:%s", subjectType)
	DeleteCache(homeCacheKey)

	homeSummaryCacheKey := fmt.Sprintf("home_summary:%s", subjectType)
	DeleteCache(homeSummaryCacheKey)

	countCacheKey := fmt.Sprintf("count:%s", subjectType)
	DeleteCache(countCacheKey)
}

// 清理新增/更新/删除操作时该分类首页缓存
func ClearPageCache(subjectType string) {
	prefix := fmt.Sprintf("page:%s:", subjectType)
	cacheItem.Range(func(key, value interface{}) bool {
		cacheKey := key.(string)
		if strings.HasPrefix(cacheKey, prefix) {
			DeleteCache(cacheKey)
		}
		return true
	})
}

// 删除最早的 subject 缓存
func deleteOldestSubjectCache() {
	for cacheSubjectOrder.Len() > 0 {
		elem := cacheSubjectOrder.Front()
		if elem == nil {
			break
		}
		key := elem.Value.(string)
		cacheSubjectOrder.Remove(elem)
		cacheSubjectIndex.Delete(key)
		cacheItem.Delete(key)
		// fmt.Printf("已删除最早的缓存: %s\n", key)
		break
	}
}

func countSubjectCache() int {
	return cacheSubjectOrder.Len()
}
