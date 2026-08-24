// Package locale provides the fixed English message catalog used by the 4x-ui panel and Telegram bot.
package locale

import (
	"embed"
	"os"
	"strings"

	"github.com/sharif102007/4x-ui/v2/logger"

	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/text/language"
)

var (
	i18nBundle   *i18n.Bundle
	LocalizerWeb *i18n.Localizer
	LocalizerBot *i18n.Localizer
)

type I18nType string

const (
	Bot I18nType = "bot"
	Web I18nType = "web"
)

// InitLocalizer loads only English. Browser locale, cookies, headers, and user language preferences are ignored.
func InitLocalizer(i18nFS embed.FS) error {
	i18nBundle = i18n.NewBundle(language.MustParse("en-US"))
	i18nBundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)

	if err := parseEnglishTranslation(i18nFS, i18nBundle); err != nil {
		return err
	}

	LocalizerWeb = i18n.NewLocalizer(i18nBundle, "en-US")
	LocalizerBot = i18n.NewLocalizer(i18nBundle, "en-US")
	return nil
}

func createTemplateData(params []string, separator ...string) map[string]any {
	sep := "=="
	if len(separator) > 0 {
		sep = separator[0]
	}

	templateData := make(map[string]any)
	for _, param := range params {
		parts := strings.SplitN(param, sep, 2)
		if len(parts) == 2 {
			templateData[parts[0]] = parts[1]
		}
	}
	return templateData
}

func I18n(i18nType I18nType, key string, params ...string) string {
	var localizer *i18n.Localizer
	switch i18nType {
	case Bot:
		localizer = LocalizerBot
	case Web:
		localizer = LocalizerWeb
	default:
		logger.Errorf("Invalid type for I18n: %s", i18nType)
		return ""
	}

	if localizer == nil {
		return key
	}

	msg, err := localizer.Localize(&i18n.LocalizeConfig{
		MessageID:    key,
		TemplateData: createTemplateData(params),
	})
	if err != nil {
		logger.Errorf("Failed to localize English message: %v", err)
		return ""
	}
	return msg
}

// LocalizerMiddleware always installs en-US and never reloads the page for locale setup.
func LocalizerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if i18nBundle == nil {
			i18nBundle = i18n.NewBundle(language.MustParse("en-US"))
			i18nBundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
			if err := loadEnglishTranslationFromDisk(i18nBundle); err != nil {
				logger.Warning("English translation lazy load failed:", err)
			}
		}

		LocalizerWeb = i18n.NewLocalizer(i18nBundle, "en-US")
		c.Set("localizer", LocalizerWeb)
		c.Set("I18n", I18n)
		c.Next()
	}
}

func loadEnglishTranslationFromDisk(bundle *i18n.Bundle) error {
	data, err := os.ReadFile("web/translation/translate.en_US.toml")
	if err != nil {
		return err
	}
	_, err = bundle.ParseMessageFileBytes(data, "translation/translate.en_US.toml")
	return err
}

func parseEnglishTranslation(i18nFS embed.FS, bundle *i18n.Bundle) error {
	data, err := i18nFS.ReadFile("translation/translate.en_US.toml")
	if err != nil {
		return err
	}
	_, err = bundle.ParseMessageFileBytes(data, "translation/translate.en_US.toml")
	return err
}
