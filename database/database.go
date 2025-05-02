package database

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/bitterspread/mediax/helpers"
	"github.com/bitterspread/mediax/models"
	"github.com/bitterspread/mediax/version"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

func GetDB() *gorm.DB {
	return db
}

func InitDB() {
	var err error
	dbLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:        time.Second,
			LogLevel:             logger.Error,
			ParameterizedQueries: true,
			Colorful:             true,
		},
	)

	dbPath := "mediax.db"

	_, err = os.Stat(dbPath)

	db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		TranslateError: true,
		Logger:         dbLogger,
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	migrateDB(db)
}

func migrateDB(db *gorm.DB) {
	if !db.Migrator().HasTable(&models.Version{}) {
		if err := db.AutoMigrate(&models.Version{}); err != nil {
			log.Fatalf("Failed to migrate Version table: %v", err)
		}
		log.Println("Table Version created.")
	}

	currentVersion := getCurrentVersion(db)

	if isOldVersion(currentVersion, "0.6.0") {
		log.Println("Migrating database from version", currentVersion, "to 0.6.0 ...")
		err := db.AutoMigrate(&models.Subject{})
		if err != nil {
			log.Fatalf("Failed to migrate database: %v", err)
		}

		// 删除过时的索引
		if db.Migrator().HasIndex(&models.Subject{}, "idx_title") {
			db.Migrator().DropIndex(&models.Subject{}, "idx_title")
		}
		if db.Migrator().HasIndex(&models.Subject{}, "idx_id_type") {
			db.Migrator().DropIndex(&models.Subject{}, "idx_id_type")
		}
		if db.Migrator().HasIndex(&models.Subject{}, "idx_type_status_id") {
			db.Migrator().DropIndex(&models.Subject{}, "idx_type_status_id")
		}

		err = setCurrentVersion(db, version.Version)
		if err != nil {
			log.Fatalf("Failed to set current version: %v", err)
		}

		log.Println("Database migration successful.")
	}
}

func getCurrentVersion(db *gorm.DB) string {
	var version models.Version
	if err := db.First(&version).Error; err != nil {
		return "0.0.0"
	}
	return version.Version
}

func setCurrentVersion(db *gorm.DB, version string) error {
	var existingVersion models.Version
	if err := db.First(&existingVersion).Error; err == nil {
		existingVersion.Version = version
		existingVersion.UpdatedAt = time.Now().Unix()
		return db.Save(&existingVersion).Error
	} else {
		newVersion := models.Version{
			Version:   version,
			UpdatedAt: time.Now().Unix(),
		}
		return db.Create(&newVersion).Error
	}
}

func isOldVersion(current, target string) bool {
	if !isValidVersionFormat(current) || !isValidVersionFormat(target) {
		return false
	}

	curParts := strings.Split(current, ".")
	tgtParts := strings.Split(target, ".")
	for i := 0; i < 3; i++ {
		cur, err1 := helpers.StringToInt(curParts[i])
		tgt, err2 := helpers.StringToInt(tgtParts[i])

		if err1 != nil || err2 != nil {
			return false
		}

		if cur < tgt {
			return true
		} else if cur > tgt {
			return false
		}
	}
	return false
}

func isValidVersionFormat(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if _, err := helpers.StringToInt(part); err != nil {
			return false
		}
	}
	return true
}
