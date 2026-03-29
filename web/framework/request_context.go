package framework

import "github.com/gin-gonic/gin"

const (
	sessionContextKey = "nps.session"
	requestDataKey    = "nps.request_data"
	requestParamsKey  = "nps.request_params"
)

func SetRequestData(g *gin.Context, key string, value interface{}) {
	data := requestDataFromContext(g)
	if data == nil {
		data = make(map[string]interface{})
		g.Set(requestDataKey, data)
	}
	data[key] = value
	g.Set(key, value)
}

func SetRequestParam(g *gin.Context, key, value string) {
	params := requestParamsFromContext(g)
	if params == nil {
		params = make(map[string]string)
		g.Set(requestParamsKey, params)
	}
	params[key] = value
}

func RequestParam(g *gin.Context, key string) (string, bool) {
	params := requestParamsFromContext(g)
	if params == nil {
		return "", false
	}
	value, ok := params[key]
	return value, ok
}

func requestDataFromContext(g *gin.Context) map[string]interface{} {
	if v, ok := g.Get(requestDataKey); ok {
		if data, ok := v.(map[string]interface{}); ok {
			return data
		}
	}
	return nil
}

func requestParamsFromContext(g *gin.Context) map[string]string {
	if v, ok := g.Get(requestParamsKey); ok {
		if params, ok := v.(map[string]string); ok {
			return params
		}
	}
	return nil
}
