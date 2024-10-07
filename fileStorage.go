package file_storage

import (
	utils "github.com/Indivizo/go-utils"
	"io"
)

// FileManager manages files at a remote location.
type FileManager interface {
	UploadFile(groupID string, itemID string, filePath string, fileMetadata map[string]interface{}) (url utils.Url, err error)
	DeleteFile(groupID string, itemID string) (err error)
	GetFileWithPrefix(prefix, filePath string) (file io.ReadSeeker, err error)
}
