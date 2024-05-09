package buildah

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/containers/buildah/pkg/blobcache"
	"github.com/containers/common/libimage"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/image"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/pkg/blobinfocache"
	"github.com/containers/image/v5/pkg/compression"
	"github.com/containers/image/v5/transports"
	"github.com/containers/image/v5/types"
	encconfig "github.com/containers/ocicrypt/config"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/archive"
	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

// cacheLookupReferenceFunc wraps a BlobCache into a
// libimage.LookupReferenceFunc to allow for using a BlobCache during
// image-copy operations.
func cacheLookupReferenceFunc(directory string, compress types.LayerCompression) libimage.LookupReferenceFunc {
	// Using a closure here allows us to reference a BlobCache without
	// having to explicitly maintain it in the libimage API.
	return func(ref types.ImageReference) (types.ImageReference, error) {
		if directory == "" {
			return ref, nil
		}
		ref, err := blobcache.NewBlobCache(ref, directory, compress)
		if err != nil {
			return nil, fmt.Errorf("using blobcache %q: %w", directory, err)
		}
		return ref, nil
	}
}

// PushOptions can be used to alter how an image is copied somewhere.
type PushOptions struct {
	Logger *logrus.Logger
	// Compression specifies the type of compression which is applied to
	// layer blobs.  The default is to not use compression, but
	// archive.Gzip is recommended.
	// OBSOLETE: Use CompressionFormat instead.
	Compression archive.Compression
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
	// ManifestType is the format to use
	// possible options are oci, v2s1, and v2s2
	ManifestType string
	// BlobDirectory is the name of a directory in which we'll look for
	// prebuilt copies of layer blobs that we might otherwise need to
	// regenerate from on-disk layers, substituting them in the list of
	// blobs to copy whenever possible.
	BlobDirectory string
	// Quiet is a boolean value that determines if minimal output to
	// the user will be displayed, this is best used for logging.
	// The default is false.
	Quiet bool
	// SignBy is the fingerprint of a GPG key to use for signing the image.
	SignBy string
	// RemoveSignatures causes any existing signatures for the image to be
	// discarded for the pushed copy.
	RemoveSignatures bool
	// MaxRetries is the maximum number of attempts we'll make to push any
	// one image to the external registry if the first attempt fails.
	MaxRetries int
	// RetryDelay is how long to wait before retrying a push attempt.
	RetryDelay time.Duration
	// OciEncryptConfig when non-nil indicates that an image should be encrypted.
	// The encryption options is derived from the construction of EncryptConfig object.
	OciEncryptConfig *encconfig.EncryptConfig
	// OciEncryptLayers represents the list of layers to encrypt.
	// If nil, don't encrypt any layers.
	// If non-nil and len==0, denotes encrypt all layers.
	// integers in the slice represent 0-indexed layer indices, with support for negative
	// indexing. i.e. 0 is the first layer, -1 is the last (top-most) layer.
	OciEncryptLayers *[]int

	// CompressionFormat is the format to use for the compression of the blobs
	CompressionFormat *compression.Algorithm
	// CompressionLevel specifies what compression level is used
	CompressionLevel *int
	// ForceCompressionFormat ensures that the compression algorithm set in
	// CompressionFormat is used exclusively, and blobs of other compression
	// algorithms are not reused.
	ForceCompressionFormat bool
}

// Push copies the contents of the image to a new location.
func Push(ctx context.Context, image string, dest types.ImageReference, options PushOptions) (reference.Canonical, digest.Digest, error) {
	libimageOptions := &libimage.PushOptions{}
	libimageOptions.SignaturePolicyPath = options.SignaturePolicyPath
	libimageOptions.Writer = options.ReportWriter
	libimageOptions.ManifestMIMEType = options.ManifestType
	libimageOptions.SignBy = options.SignBy
	libimageOptions.RemoveSignatures = options.RemoveSignatures
	libimageOptions.RetryDelay = &options.RetryDelay
	libimageOptions.OciEncryptConfig = options.OciEncryptConfig
	libimageOptions.OciEncryptLayers = options.OciEncryptLayers
	libimageOptions.CompressionFormat = options.CompressionFormat
	libimageOptions.CompressionLevel = options.CompressionLevel
	libimageOptions.ForceCompressionFormat = options.ForceCompressionFormat
	libimageOptions.PolicyAllowStorage = true

	if options.Quiet {
		libimageOptions.Writer = nil
	}

	compress := types.PreserveOriginal
	if options.Compression == archive.Gzip || options.Compression == archive.Zstd {
		compress = types.Compress
	}
	realBlobCache := cacheLookupReferenceFunc(options.BlobDirectory, compress)
	libimageOptions.SourceLookupReferenceFunc = func(ref types.ImageReference) (types.ImageReference, error) {
		options.Logger.Debugf("Looking up source image %q %q", ref.Transport().Name(), ref.StringWithinTransport())
		src, err := realBlobCache(ref)
		return stubbedBlobsImageReference{
			ImageReference: src,
			destRef:        dest,
			logger:         options.Logger,
		}, err
	}

	runtime, err := libimage.RuntimeFromStore(options.Store, &libimage.RuntimeOptions{SystemContext: options.SystemContext})
	if err != nil {
		return nil, "", err
	}

	destString := fmt.Sprintf("%s:%s", dest.Transport().Name(), dest.StringWithinTransport())
	manifestBytes, err := runtime.Push(ctx, image, destString, libimageOptions)
	if err != nil {
		return nil, "", err
	}

	manifestDigest, err := manifest.Digest(manifestBytes)
	if err != nil {
		return nil, "", fmt.Errorf("computing digest of manifest of new image %q: %w", transports.ImageName(dest), err)
	}

	var ref reference.Canonical
	if name := dest.DockerReference(); name != nil {
		ref, err = reference.WithDigest(name, manifestDigest)
		if err != nil {
			logrus.Warnf("error generating canonical reference with name %q and digest %s: %v", name, manifestDigest.String(), err)
		}
	}

	return ref, manifestDigest, nil
}

type stubbedBlobsImageReference struct {
	types.ImageReference
	destRef types.ImageReference
	logger  *logrus.Logger
}

func (ref stubbedBlobsImageReference) NewImageSource(ctx context.Context, sys *types.SystemContext) (types.ImageSource, error) {
	src, err := ref.ImageReference.NewImageSource(ctx, sys)
	return stubbedBlobsImageSource{
		ImageSource: src,
		destRef:     ref.destRef,
		logger:      ref.logger,
		cache:       blobinfocache.DefaultCache(sys),
	}, err
}

type stubbedBlobsImageSource struct {
	types.ImageSource
	destRef types.ImageReference
	logger  *logrus.Logger
	cache   types.BlobInfoCache
}

func (src stubbedBlobsImageSource) LayerInfosForCopy(ctx context.Context, instanceDigest *digest.Digest) ([]types.BlobInfo, error) {
	updatedBlobInfos := []types.BlobInfo{}
	infos, err := src.ImageSource.LayerInfosForCopy(ctx, instanceDigest)
	if err != nil {
		return nil, err
	}
	if infos == nil {
		return nil, nil
	}

	manifestBlob, manifestType, err := src.GetManifest(ctx, instanceDigest)
	if err != nil {
		return nil, fmt.Errorf("reading image manifest: %w", err)
	}
	if manifest.MIMETypeIsMultiImage(manifestType) {
		return nil, errors.New("can't copy layers for a manifest list (shouldn't be attempted)")
	}

	var manifestStub struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(manifestBlob, &manifestStub); err != nil {
		return nil, fmt.Errorf("parsing image manifest in LayerInfosForCopy: %w", err)
	}

	baseImageRegistry := ""
	if baseImage, ok := manifestStub.Annotations["org.opencontainers.image.base.name"]; ok {
		if registry, _, ok := strings.Cut(baseImage, "/"); ok {
			baseImageRegistry = registry
			src.logger.Debugf("found base image registry %s", baseImageRegistry)
		}
	}

	destRegistry := reference.Domain(src.destRef.DockerReference())

	changed := false
	for _, layerBlob := range infos {
		src.logger.Debugf("blob %s", layerBlob.Digest)
		var candidates []types.BICReplacementCandidate
		if baseImageRegistry != "" {
			candidates = src.cache.CandidateLocations(docker.Transport, types.BICTransportScope{Opaque: baseImageRegistry}, layerBlob.Digest, true)
			if len(candidates) == 0 {
				candidates = src.cache.CandidateLocations(docker.Transport, types.BICTransportScope{Opaque: destRegistry}, layerBlob.Digest, false)
			}
		}
		if len(candidates) > 0 {
			// We have a cached blob reference for this layer - that means
			// we've pulled or pushed it before and there's no need to push
			// it to cache.
			src.logger.Debugf("stubbing layer %s", layerBlob.Digest)
			blobInfo := types.BlobInfo{
				Digest:    image.GzippedEmptyLayerDigest,
				Size:      int64(len(image.GzippedEmptyLayer)),
				MediaType: imgspecv1.MediaTypeImageLayerGzip,
				Annotations: map[string]string{
					diffIDAnnotation: layerBlob.Digest.String(),
				},
			}
			updatedBlobInfos = append(updatedBlobInfos, blobInfo)
			changed = true
		} else {
			updatedBlobInfos = append(updatedBlobInfos, layerBlob)
		}
	}
	if changed {
		return updatedBlobInfos, nil
	}
	return infos, nil
}

func (src stubbedBlobsImageSource) GetBlob(ctx context.Context, info types.BlobInfo, infoCache types.BlobInfoCache) (io.ReadCloser, int64, error) {
	if info.Digest == image.GzippedEmptyLayerDigest {
		src.logger.Debugf("returning empty blob")
		return io.NopCloser(bytes.NewReader(image.GzippedEmptyLayer)), int64(len(image.GzippedEmptyLayer)), nil
	}
	return src.ImageSource.GetBlob(ctx, info, infoCache)
}
