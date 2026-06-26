# Project Architecture

## Overview
Provide a high-level summary of the system and its purpose.

## Technology Stack
- **Language:** Node.js
- **Cloud Provider:** Google Cloud Platform (GCS, Vertex AI)
- **Key Libraries:** `@google-cloud/storage`, `@google/genai`

## Component Breakdown
### 1. Storage Layer
Uses Google Cloud Storage for persistent object storage. Data integrity is maintained using CRC32C checksums during uploads/downloads.

### 2. AI Integration
Integrates with Vertex AI / Gemini API for generative tasks.

## Data Flow
1. User initiates a request via the CLI/Browser.
2. Application fetches necessary context/assets from GCS.
3. Context is sent to the Gemini API for processing.
4. Results are returned to the user and optionally cached back in GCS.

## Security & Compliance
- Service Account authentication via Application Default Credentials (ADC).
- Customer-Supplied Encryption Keys (CSEK) for sensitive data in GCS.