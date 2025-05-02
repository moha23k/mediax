package models

// Database / Detail
// Status - 1: 想看, 2: 在看, 3: 已看 (4: 搁置, 5: 抛弃)
type Subject struct {
	ID          uint   `gorm:"primaryKey;index:idx_type_id_status,priority:2;column:id"`
	UUID        string `gorm:"size:36;unique;column:uuid"`
	SubjectType string `gorm:"size:16;index:idx_type_id_status,priority:1;index:idx_type_mark_status,priority:1;column:subject_type"`
	Title       string `gorm:"size:255;column:title"`
	AltTitle    string `gorm:"size:255;column:alt_title"`
	Creator     string `gorm:"size:512;column:creator"`
	Press       string `gorm:"size:255;column:press"`
	Status      int    `gorm:"index:idx_type_id_status,priority:3;index:idx_type_mark_status,priority:3;column:status"`
	Rating      int    `gorm:"column:rating"`
	ExternalURL string `gorm:"size:255;index:idx_external_url;column:external_url"`
	HasImage    int    `gorm:"column:has_image"`
	Summary     string `gorm:"type:text;column:summary"`
	Comment     string `gorm:"type:text;column:comment"`
	PubDate     string `gorm:"size:36;column:pub_date"`
	MarkDate    string `gorm:"size:36;index:idx_type_mark_status,priority:2;column:mark_date"`
	CreatedAt   int64  `gorm:"column:created_at"`
	UpdatedAt   int64  `gorm:"column:updated_at"`
}

func (Subject) TableName() string {
	return "subject"
}

type Version struct {
	ID        uint   `gorm:"primaryKey"`
	Version   string `gorm:"unique;column:version"`
	UpdatedAt int64  `gorm:"column:updated_at"`
}

func (Version) TableName() string {
	return "version"
}
