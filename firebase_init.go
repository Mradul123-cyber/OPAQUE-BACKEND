package main

import (
	"context"
	"fmt"
	"os"

	"firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"firebase.google.com/go/v4/messaging"
	"google.golang.org/api/option"
)

var (
    firebaseApp  *firebase.App
    firebaseAuth *auth.Client
    fcmClient    *messaging.Client
    ctx          = context.Background()
)

func initFirebase() error {
    // Read Firebase credentials path from environment variable
    credentialsPath := os.Getenv("FIREBASE_CREDENTIALS_PATH")
    if credentialsPath == "" {
        credentialsPath = "serviceAccountKey.json" // fallback default
    }

    opt := option.WithCredentialsFile(credentialsPath)
    
    app, err := firebase.NewApp(ctx, nil, opt)
    if err != nil {
        return fmt.Errorf("failed to initialize Firebase app: %v", err)
    }
    firebaseApp = app

    // Initialize Auth
    firebaseAuth, err = app.Auth(ctx)
    if err != nil {
        return fmt.Errorf("failed to initialize Firebase Auth: %v", err)
    }

    // Initialize FCM
    fcmClient, err = app.Messaging(ctx)
    if err != nil {
        return fmt.Errorf("failed to initialize FCM client: %v", err)
    }

    return nil
}