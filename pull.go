package buildah

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/containers/buildah/define"
	"github.com/containers/common/libimage"
	"github.com/containers/common/pkg/config"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
	encconfig "github.com/containers/ocicrypt/config"
	"github.com/containers/storage"
	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

// PullOptions can be used to alter how an image is copied in from somewhere.
type PullOptions struct {
	Logger *logrus.Logger
	// SignaturePolicyPath specifies an override location for the signature
	// policy which should be used for verifying the new image as it is
	// being written.  Except in specific circumstances, no value should be
	// specified, indicating that the shared, system-wide default policy
	// should be used.
	SignaturePolicyPath string
	// ReportWriter is an io.Writer which will be used to log the writing
	// of the new image.
	ReportWriter io.Writer
	// Store is the local storage store which holds the source image.
	Store storage.Store
	// github.com/containers/image/types SystemContext to hold credentials
	// and other authentication/authorization information.
	SystemContext *types.SystemContext
	// BlobDirectory is the name of a directory in which we'll attempt to
	// store copies of layer blobs that we pull down, if any.  It should
	// already exist.
	BlobDirectory string
	// AllTags is a boolean value that determines if all tagged images
	// will be downloaded from the repository. The default is false.
	AllTags bool
	// RemoveSignatures causes any existing signatures for the image to be
	// discarded when pulling it.
	RemoveSignatures bool
	// MaxRetries is the maximum number of attempts we'll make to pull any
	// one image from the external registry if the first attempt fails.
	MaxRetries int
	// RetryDelay is how long to wait before retrying a pull attempt.
	RetryDelay time.Duration
	// OciDecryptConfig contains the config that can be used to decrypt an image if it is
	// encrypted if non-nil. If nil, it does not attempt to decrypt an image.
	OciDecryptConfig *encconfig.DecryptConfig
	// PullPolicy takes the value PullIfMissing, PullAlways, PullIfNewer, or PullNever.
	PullPolicy define.PullPolicy
}

// Pull copies the contents of the image from somewhere else to local storage.  Returns the
// ID of the local image or an error.
func Pull(ctx context.Context, imageName string, options PullOptions) (imageID string, err error) {
	libimageOptions := &libimage.PullOptions{}
	libimageOptions.SignaturePolicyPath = options.SignaturePolicyPath
	libimageOptions.Writer = options.ReportWriter
	libimageOptions.RemoveSignatures = options.RemoveSignatures
	libimageOptions.OciDecryptConfig = options.OciDecryptConfig
	libimageOptions.AllTags = options.AllTags
	libimageOptions.RetryDelay = &options.RetryDelay
	logger := logrus.StandardLogger()
	if options.Logger != nil {
		logger = options.Logger
	}
	libimageOptions.SourceLookupReferenceFunc = func(ref types.ImageReference) (types.ImageReference, error) {
		return substituteStubbedBlobsRef{
			ImageReference: ref,
			logger:         logger,
		}, err
	}
	libimageOptions.DestinationLookupReferenceFunc = cacheLookupReferenceFunc(options.BlobDirectory, types.PreserveOriginal)

	if options.MaxRetries > 0 {
		retries := uint(options.MaxRetries)
		libimageOptions.MaxRetries = &retries
	}

	pullPolicy, err := config.ParsePullPolicy(options.PullPolicy.String())
	if err != nil {
		return "", err
	}

	// Note: It is important to do this before we pull any images/create containers.
	// The default backend detection logic needs an empty store to correctly detect
	// that we can use netavark, if the store was not empty it will use CNI to not break existing installs.
	_, err = getNetworkInterface(options.Store, "", "")
	if err != nil {
		return "", err
	}

	runtime, err := libimage.RuntimeFromStore(options.Store, &libimage.RuntimeOptions{SystemContext: options.SystemContext})
	if err != nil {
		return "", err
	}

	pulledImages, err := runtime.Pull(context.Background(), imageName, pullPolicy, libimageOptions)
	if err != nil {
		return "", err
	}

	if len(pulledImages) == 0 {
		return "", fmt.Errorf("internal error pulling %s: no image pulled and no error", imageName)
	}

	return pulledImages[0].ID(), nil
}

type substituteStubbedBlobsRef struct {
	types.ImageReference
	logger *logrus.Logger
}

func (ref substituteStubbedBlobsRef) NewImageSource(ctx context.Context, sys *types.SystemContext) (types.ImageSource, error) {
	src, err := ref.ImageReference.NewImageSource(ctx, sys)
	return recordPulledBlobsImageSource{ImageSource: src, logger: ref.logger}, err
}

type recordPulledBlobsImageSource struct {
	types.ImageSource
	logger *logrus.Logger
}

const diffIDAnnotation = "diffid"

func (src recordPulledBlobsImageSource) LayerInfosForCopy(ctx context.Context, instanceDigest *digest.Digest) ([]types.BlobInfo, error) {
	manifestBlob, manifestType, err := src.GetManifest(ctx, instanceDigest)
	if err != nil {
		return nil, fmt.Errorf("reading image manifest: %w", err)
	}
	if manifest.MIMETypeIsMultiImage(manifestType) {
		return nil, errors.New("can't copy layers for a manifest list (shouldn't be attempted)")
	}
	man, err := manifest.FromBlob(manifestBlob, manifestType)
	if err != nil {
		return nil, fmt.Errorf("parsing image manifest for: %w", err)
	}

	uncompressedLayerType := ""
	switch manifestType {
	case imgspecv1.MediaTypeImageManifest:
		uncompressedLayerType = imgspecv1.MediaTypeImageLayer
	case manifest.DockerV2Schema1MediaType, manifest.DockerV2Schema1SignedMediaType, manifest.DockerV2Schema2MediaType:
		uncompressedLayerType = manifest.DockerV2SchemaLayerMediaTypeUncompressed
	}

	var (
		changed    bool
		layerInfos []types.BlobInfo
	)
	for _, layerInfo := range man.LayerInfos() {
		src.logger.Debugf("layer digest: %s, annotations: %v", layerInfo.Digest.String(), layerInfo.Annotations)
		if diffID := layerInfo.Annotations[diffIDAnnotation]; diffID != "" {
			src.logger.Debugf("using diffid %s", diffID)
			diffIDDigest, err := digest.Parse(diffID)
			if err != nil {
				return nil, fmt.Errorf("parsing diffid %q: %w", diffID, err)
			}
			layerInfos = append(layerInfos, types.BlobInfo{
				Digest:    diffIDDigest,
				Size:      -1,
				MediaType: uncompressedLayerType,
			})
			changed = true
		} else {
			layerInfos = append(layerInfos, layerInfo.BlobInfo)
		}
	}
	if changed {
		src.logger.Infof("Reusing existing layers on disk which were stubbed in cache push")
		return layerInfos, nil
	}

	return src.ImageSource.LayerInfosForCopy(ctx, instanceDigest)
}
