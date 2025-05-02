package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bitterspread/mediax/config"
	"github.com/bitterspread/mediax/dataops"
	"github.com/bitterspread/mediax/helpers"
)

func HandleAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")

	switch r.Method {
	case http.MethodGet:
		query := r.URL.Query()
		subjectType := query.Get("type")
		queryLimit := query.Get("limit")
		queryOffset := query.Get("offset")
		querySort := query.Get("sort")

		validTypes := map[string]bool{
			"all":   true,
			"book":  true,
			"movie": true,
			"tv":    true,
			"anime": true,
			"game":  true,
		}
		if subjectType == "" {
			subjectType = "all"
		} else if !validTypes[subjectType] {
			HandleAPIError(w, http.StatusBadRequest, "invalid subject type")
			return
		}

		limit := config.QueryLimit
		if queryLimit != "" {
			var err error
			limit, err = helpers.StringToInt(queryLimit)
			if err != nil {
				HandleAPIError(w, http.StatusBadRequest, "invalid limit")
				return
			}
			if limit < 1 || limit > config.QueryLimit {
				limit = config.QueryLimit
			}
		}

		offset := 0
		if queryOffset != "" {
			var err error
			offset, err = helpers.StringToInt(queryOffset)
			if err != nil {
				HandleAPIError(w, http.StatusBadRequest, "invalid offset")
				return
			}
			if offset < 1 {
				offset = 0
			}
		}

		sort := 1
		if querySort != "" {
			var err error
			sort, err = helpers.StringToInt(querySort)
			if err != nil {
				HandleAPIError(w, http.StatusBadRequest, "invalid sort")
				return
			}
			if sort < 1 || sort > 4 {
				HandleAPIError(w, http.StatusBadRequest, "invalid sort")
				return
			}
		}

		responseJSON, err := dataops.ExportToJSONAPI(subjectType, limit, offset, sort)
		if err != nil {
			HandleAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Write(responseJSON)
		return
	default:
		HandleAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
}

type apiError struct {
	Error     string `json:"error"`
	Timestamp string `json:"timestamp"`
}

func HandleAPIError(w http.ResponseWriter, errStatus int, errMessage string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errStatus)

	currentTimeUTC := time.Now().UTC()
	timestampStr := currentTimeUTC.Format(time.RFC3339)

	response := apiError{
		Error:     errMessage,
		Timestamp: timestampStr,
	}
	jsonResponse, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		http.Error(w, "Internal Server Error marshalling error response", http.StatusInternalServerError)
		return
	}
	w.Write(jsonResponse)
}
