package variable

import "strings"

type model struct {
	key   string
	value string
}

// Order is important because some model also includes other key,
// so we define model order from specific platform
var models = []model{
	{key: "nintendo switch", value: "Switch"},
	{key: "nintendo 3ds", value: "3DS"},
	{key: "xbox one", value: "Xbox One"},
	{key: "xbox", value: "Xbox 360"},
	{key: "kindle fire", value: "Kindle Fire"},
	{key: "kindle", value: "Kindle"},
	{key: "playstation 3", value: "PlayStation 3"},
	{key: "playstation 4", value: "PlayStation 4"},
	{key: "playstation 5", value: "PlayStation 5"},
	{key: "iphone", value: "iPhone"},
}

func getPlatformModel(userAgent string) string {
	ua := strings.ToLower(userAgent)

	for _, model := range models {
		if strings.Contains(ua, model.key) {
			return model.value
		}
	}
	return ""
}

type vendor struct {
	key   string
	value string
}

// Order is important because some vendor also includes other key,
// so we define vendor order from specific platform
var vendors = []vendor{
	{key: "nintendo", value: "Nintendo"},
	{key: "xbox", value: "Microsoft"},
	{key: "kindle", value: "Amazon"},
	{key: "playstation", value: "Sony"},
	{key: "playstation 4", value: "PlayStation 4"},
	{key: "playstation 5", value: "PlayStation 5"},
	{key: "iphone", value: "Apple"},
	{key: "ipad", value: "Apple"},
	{key: "ipod", value: "Apple"},
	{key: "macintosh", value: "Apple"},
	{key: "mac", value: "Apple"},
}

func getPlatformVendor(userAgent string) string {
	ua := strings.ToLower(userAgent)

	for _, vendor := range vendors {
		if strings.Contains(ua, vendor.key) {
			return vendor.value
		}
	}
	return ""
}
