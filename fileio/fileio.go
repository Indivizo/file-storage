package fileio

import (
	"bytes"
	"encoding/json"
	"fmt"
	filestorage "github.com/Indivizo/file-storage"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	utils "github.com/Indivizo/go-utils"
)

type Uploader struct{}

// UploadFile uploads a file to File.io and returns a download URL
func (f Uploader) UploadFile(groupID string, itemID string, filePath string, fileMetadata map[string]interface{}) (utils.Url, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("unable to open file: %v", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(file.Name()))
	if err != nil {
		return "", fmt.Errorf("unable to create form file: %v", err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return "", fmt.Errorf("unable to copy file to form: %v", err)
	}

	writer.Close()

	req, err := http.NewRequest("POST", "https://file.io", body)
	if err != nil {
		return "", fmt.Errorf("unable to create new request: %v", err)
	}

	req.Header.Add("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error uploading file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to upload file, status: %v", resp.Status)
	}

	// Parse the JSON response
	var result struct {
		Success bool   `json:"success"`
		Link    string `json:"link"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", fmt.Errorf("unable to parse response: %v", err)
	}

	if !result.Success {
		return "", fmt.Errorf("file upload failed")
	}

	// Return the file URL
	fileURL := utils.Url(result.Link)
	return fileURL, nil
}

// DeleteFile returns an error as deletion is not supported in File.io
func (f Uploader) DeleteFile(groupID string, itemID string) error {
	return fmt.Errorf("file deletion is not supported by File.io")
}

var _ filestorage.FileManager = (*Uploader)(nil)
