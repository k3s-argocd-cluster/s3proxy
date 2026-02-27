package s3

import (
	"bytes"
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go/modules/minio"
)

type S3ClientTestSuite struct {
	suite.Suite
	Context     context.Context
	Config      *aws.Config
	AdminClient *s3.Client
}

func (s *S3ClientTestSuite) SetupSuite() {
	s.Context = context.Background()

	container, err := minio.Run(s.Context, "minio/minio:RELEASE.2024-01-16T16-07-38Z")
	if err != nil {
		panic(errors.WithStack(err))
	}

	connection, err := container.ConnectionString(s.Context)
	if err != nil {
		panic(errors.WithStack(err))
	}

	endpoint := "http://" + connection

	s.Config = aws.NewConfig()
	s.Config.Credentials = credentials.NewStaticCredentialsProvider(container.Username, container.Password, "")
	s.Config.Region = "default"
	s.Config.BaseEndpoint = &endpoint

	s.AdminClient = s3.NewFromConfig(*s.Config)
}

func (s *S3ClientTestSuite) BeforeTest(suiteName, testName string) {
	bucket := "test"
	_, err := s.AdminClient.CreateBucket(s.Context, &s3.CreateBucketInput{
		Bucket: &bucket,
	})

	if err != nil {
		panic(errors.WithStack(err))
	}
}

func (mySuite *S3ClientTestSuite) TestIntegration_Something_WriteToBucket() {
	_, err := mySuite.AdminClient.PutObject(mySuite.Context, &s3.PutObjectInput{
		Bucket: aws.String("test"),
		Key:    aws.String("some-item"),
		Body:   bytes.NewReader([]byte("hallo welt")),
	})

	mySuite.NoError(err)
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestIntegration_S3ClientTestSuite(t *testing.T) {
	suite.Run(t, new(S3ClientTestSuite))
}
