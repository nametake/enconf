package main

import (
	"context"
	"encoding/base64"
	"fmt"

	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

func encrypt(ctx context.Context, projectID, locationID, keyRingID, cryptoKeyID, text string) (string, error) {
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return "", err
	}

	kmsService, err := cloudkms.New(client)
	if err != nil {
		return "", err
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", projectID, locationID, keyRingID, cryptoKeyID)
	req := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString([]byte(text)),
	}
	resp, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(parentName, req).Do()
	if err != nil {
		return "", err
	}

	return resp.Ciphertext, nil
}

func decrypt(ctx context.Context, projectID, locationID, keyRingID, cryptoKeyID, text string) (string, error) {
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return "", err
	}

	kmsService, err := cloudkms.New(client)
	if err != nil {
		return "", err
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", projectID, locationID, keyRingID, cryptoKeyID)
	req := &cloudkms.DecryptRequest{
		Ciphertext: text,
	}
	resp, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(parentName, req).Do()
	if err != nil {
		return "", err
	}

	origin, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return "", err
	}

	return string(origin), nil
}
