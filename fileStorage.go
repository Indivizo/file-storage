package file_storage

import (
	utils "github.com/Indivizo/go-utils"
)

// FileManager manages files at a remote location.
type FileManager interface {
	UploadFile(groupID string, itemID string, filePath string, fileMetadata map[string]interface{}) (url utils.Url, err error)
	DeleteFile(groupID string, itemID string) (err error)
}
