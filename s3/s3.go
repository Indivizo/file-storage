package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	filestorage "github.com/Indivizo/file-storage"
	"net/url"
	"os"
	"strings"
	"time"

	utils "github.com/Indivizo/go-utils"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Region is the s3 region we use by default: the Frankfurt region.
const Region = "eu-central-1"

const timeFormatLong = "20060102T150405Z"
const timeFormatShort = "20060102"
const authorizationAlgorithm = "AWS4-HMAC-SHA256"

const accelerationStatusEnabled = "Enabled"

// MaxFileSize is the maximum size of files we will accept uploading to s3.
const MaxFileSize = 1024 * 1024 * 1024

// Uploader manages file uploading to S3.
type Uploader struct {
	session *s3.S3
	Debug   bool
}

func getS3ObjectName(groupID string, itemID string) string {
	return groupID + "/" + itemID
}

// UploadFile Uploads a file to amazon s3.
// For a successful upload the S3 environment has to be configured based on https://github.com/aws/aws-sdk-go/wiki/configuring-sdk.
func (s3up Uploader) UploadFile(groupID string, itemID string, filePath string, fileMetadata map[string]interface{}) (url utils.Url, err error) {
	var file *os.File
	var bucket string
	itemName := getS3ObjectName(groupID, itemID)
	if value, ok := fileMetadata["extension"]; ok {
		itemName += "." + value.(string)
	}

	if bucket, err = GetBucketName(); err != nil {
		return "", err
	}

	if file, err = os.Open(filePath); err != nil {
		return "", fmt.Errorf("failed to open the given filePath %s: %w", filePath, err)
	}
	defer file.Close()

	session := s3up.getSession()
	if err = s3up.ensureBucket(bucket); err != nil {
		return "", err
	}

	putObject := &s3.PutObjectInput{
		Body:   file,
		Bucket: &bucket,
		Key:    &itemName,
	}

	if value, ok := fileMetadata["ContentType"]; ok {
		contentType := value.(string)
		putObject.ContentType = &contentType
	}

	if value, ok := fileMetadata["filename"]; ok {
		originalFilename := value.(string)
		contentDisposition := fmt.Sprintf(`attachment; filename="%s"`, originalFilename)
		putObject.ContentDisposition = &contentDisposition
	}

	_, err = session.PutObject(putObject)
	if err != nil {
		return "", fmt.Errorf("failed to put object %s: %w", putObject, err)
	}

	return utils.Url("https://s3." + Region + ".amazonaws.com/" + bucket + "/" + itemName), err
}

func (s3up Uploader) DeleteFile(groupID string, itemID string) (err error) {
	var bucket string
	itemName := getS3ObjectName(groupID, itemID)

	if bucket, err = GetBucketName(); err != nil {
		return err
	}

	session := s3up.getSession()

	_, err = session.DeleteObject(&s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &itemName,
	})
	if err != nil {
		return fmt.Errorf("failed to delete item %s from bucket  %s: %w", itemName, bucket, err)
	}

	return nil
}

func (s3up *Uploader) getSession() *s3.S3 {
	// Set up session if there is none yet.
	if s3up.session == nil {
		var loglevel aws.LogLevelType

		if s3up.Debug {
			loglevel = aws.LogDebugWithSigning | aws.LogDebugWithHTTPBody | aws.LogDebugWithRequestErrors
		}

		config := &aws.Config{
			Region:   aws.String(Region),
			LogLevel: aws.LogLevel(loglevel),
		}
		s3up.session = s3.New(session.New(config))
	}

	return s3up.session
}

// GetBucketName retrieves the bucket we upload to.
// The default format is indivizo-videorecordings-[hostname], this value can be overridden by the s3Bucket variable.
func GetBucketName() (string, error) {
	s3Bucket := viper.GetString("s3Bucket")
	if s3Bucket == "" {
		baseURL := viper.GetString("baseUrl")
		url, err := url.Parse(baseURL)
		if err != nil {
			return "", fmt.Errorf("failed to parse baseUrl %s: %w", baseURL, err)
		}

		s3Bucket = "indivizo-videorecordings-" + strings.Replace(url.Host, ":", "-", -1)
	}

	// We cannot have dots in our bucket names.
	// https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html#transfer-acceleration-requirements
	if strings.Contains(s3Bucket, ".") {
		log.WithField("bucket", s3Bucket).Warning("Bucket contains illegal character(s)")
		s3Bucket = strings.Replace(s3Bucket, ".", "-", -1)
		log.WithField("bucket", s3Bucket).Warning("New bucket name")
	}

	return s3Bucket, nil
}

// ensureBucket makes sure a bucket exists. If it doesn't, it creates it.
func (s3up Uploader) ensureBucket(bucketName string) (err error) {
	_, err = s3up.getSession().HeadBucket(&s3.HeadBucketInput{
		Bucket: &bucketName,
	})

	if err != nil {
		log.WithField("Bucket", bucketName).Warning("Bucket doesn't exists")
		err = s3up.createBucket(bucketName)
		return err
	}

	return nil
}

// GetS3Uploadendpoint returns the url to upload an s3 object for a bucket.
// If the bucket is accelerated, it returns the accelerated url.
func (s3up Uploader) GetS3Uploadendpoint(bucket string) string {
	defaultEndpoint := "https://" + bucket + ".s3." + Region + ".amazonaws.com/"
	acceleratedEndpoint := "https://" + bucket + ".s3-accelerate.amazonaws.com/"

	acceleration, err := s3up.getSession().GetBucketAccelerateConfiguration(&s3.GetBucketAccelerateConfigurationInput{
		Bucket: &bucket,
	})
	if err != nil || acceleration.Status == nil {
		log.WithFields(log.Fields{"bucket": bucket, "error": err, "accelerationResponse": acceleration}).Warning("Unable to get transfer acceleration settings, defaulting to not accelerated")
		return defaultEndpoint
	}

	if *acceleration.Status == accelerationStatusEnabled {
		return acceleratedEndpoint
	}

	return defaultEndpoint
}

func (s3up Uploader) createBucket(bucketName string) error {
	session := s3up.getSession()

	// Create the bucket
	_, err := session.CreateBucket(&s3.CreateBucketInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return fmt.Errorf("failed to create bucket %s: %w", bucketName, err)
	}

	// Wait for the bucket to be created
	err = session.WaitUntilBucketExists(&s3.HeadBucketInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return fmt.Errorf("failed to wait for bucket %s to exist: %w", bucketName, err)
	}

	// Disable Block Public Access settings for the bucket
	_, err = session.PutPublicAccessBlock(&s3.PutPublicAccessBlockInput{
		Bucket: &bucketName,
		PublicAccessBlockConfiguration: &s3.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(false),
			IgnorePublicAcls:      aws.Bool(false),
			BlockPublicPolicy:     aws.Bool(false),
			RestrictPublicBuckets: aws.Bool(false),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to disable public access block for bucket %s: %w", bucketName, err)
	}

	// Set public read bucket policy
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::%s/*"
			}
		]
	}`

	_, err = session.PutBucketPolicy(&s3.PutBucketPolicyInput{
		Bucket: &bucketName,
		Policy: aws.String(fmt.Sprintf(policy, bucketName)),
	})
	if err != nil {
		return fmt.Errorf("failed to set public policy for bucket %s: %w", bucketName, err)
	}

	// Set CORS configuration
	_, err = session.PutBucketCors(&s3.PutBucketCorsInput{
		Bucket: &bucketName,
		CORSConfiguration: &s3.CORSConfiguration{
			CORSRules: []*s3.CORSRule{
				{
					AllowedMethods: []*string{aws.String("POST")},
					AllowedOrigins: []*string{aws.String("*")},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to set CORS configuration for bucket %s: %w", bucketName, err)
	}

	return nil
}

type PolicyConditions struct {
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	ContentType string `json:"Content-Type"`
	Date        string `json:"x-amz-date"`
	Credential  string `json:"x-amz-credential"`
	Acl         string `json:"acl"`
	Algorithm   string `json:"x-amz-algorithm"`
	FileSize    int64  `json:"-"`
}

func (pc PolicyConditions) AsList() []interface{} {
	return []interface{}{
		map[string]string{"bucket": pc.Bucket},
		map[string]string{"key": pc.Key},
		map[string]string{"Content-Type": pc.ContentType},
		map[string]string{"x-amz-date": pc.Date},
		map[string]string{"x-amz-credential": pc.Credential},
		map[string]string{"acl": pc.Acl},
		map[string]string{"x-amz-algorithm": pc.Algorithm},
		[]interface{}{"content-length-range", 0, pc.FileSize},
	}
}

type PoliciesForm struct {
	AWSAccessKeyID string `json:"AWSAccessKeyId"`
	ObjectKey      string `json:"key"`
	ContentType    string `json:"Content-Type"`
	Signature      string `json:"X-Amz-Signature"`
	Policy         string `json:"Policy"`
	Algorithm      string `json:"X-Amz-Algorithm"`
	Date           string `json:"X-Amz-Date"`
	Credential     string `json:"X-Amz-Credential"`
	Acl            string `json:"acl"`
}

type PolicyResponse struct {
	Form   PoliciesForm `json:"form"`
	Bucket string       `json:"bucket"`
	URL    string       `json:"url"`
}

type PolicyRequest struct {
	Expiration          time.Time     `json:"-"`
	ExpirationFormatted string        `json:"expiration"`
	Conditions          []interface{} `json:"conditions"`
}

func (s3up Uploader) getCredential() (string, error) {
	session := s3up.getSession()

	credentials, err := session.Client.Config.Credentials.Get()
	shortDate := time.Now().Format(timeFormatShort)

	return credentials.AccessKeyID + "/" + shortDate + "/" + Region + "/s3/aws4_request", err
}

func (s3up Uploader) getBrowserUploadPolicy(bucket, fileName string, fileSize int64, contentType string) (PolicyRequest, error) {
	credential, err := s3up.getCredential()
	if err != nil {
		return PolicyRequest{}, err
	}

	return PolicyRequest{
		ExpirationFormatted: time.Now().Add(time.Hour).Format(time.RFC3339),
		Conditions: PolicyConditions{
			Bucket:      bucket,
			Key:         fileName,
			ContentType: contentType,
			Date:        time.Now().Format(timeFormatLong),
			Credential:  credential,
			Acl:         s3.ObjectCannedACLPublicRead,
			Algorithm:   authorizationAlgorithm,
			FileSize:    fileSize,
		}.AsList(),
	}, nil
}

func (s3up Uploader) GetBrowserUploadRequest(groupID string, itemID string, fileSize int64, contentType string) (PolicyResponse, error) {
	fileName := getS3ObjectName(groupID, itemID)

	bucket, err := GetBucketName()
	if err != nil {
		return PolicyResponse{}, err
	}
	if err = s3up.ensureBucket(bucket); err != nil {
		return PolicyResponse{}, err
	}

	credential, err := s3up.getCredential()
	if err != nil {
		return PolicyResponse{}, err
	}

	credentials, err := s3up.getSession().Client.Config.Credentials.Get()
	if err != nil {
		return PolicyResponse{}, err
	}

	request, err := s3up.getBrowserUploadPolicy(bucket, fileName, fileSize, contentType)
	if err != nil {
		return PolicyResponse{}, err
	}

	policy, err := json.Marshal(request)
	if err != nil {
		return PolicyResponse{}, err
	}

	encodedPolicy := base64.StdEncoding.EncodeToString(policy)

	// The date we are going to sign the request against.
	date := time.Now()

	// Sign policy.
	// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html#signing-request-intro.
	dateKey := makeHmac([]byte("AWS4"+credentials.SecretAccessKey), []byte(date.Format(timeFormatShort)))
	regionKey := makeHmac(dateKey, []byte(Region))
	serviceKey := makeHmac(regionKey, []byte("s3"))
	requestKey := makeHmac(serviceKey, []byte("aws4_request"))
	signature := hex.EncodeToString(makeHmac(requestKey, []byte(encodedPolicy)))

	url := s3up.GetS3Uploadendpoint(bucket)

	return PolicyResponse{
		URL:    url,
		Bucket: bucket,
		Form: PoliciesForm{
			AWSAccessKeyID: credentials.AccessKeyID,
			ObjectKey:      fileName,
			ContentType:    contentType,
			Signature:      signature,
			Policy:         encodedPolicy,
			Algorithm:      authorizationAlgorithm,
			Acl:            s3.ObjectCannedACLPublicRead,
			Date:           date.Format(timeFormatLong),
			Credential:     credential,
		},
	}, nil
}

func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

var _ filestorage.FileManager = (*Uploader)(nil)
