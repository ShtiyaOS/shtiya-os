# Shtiya OS: Node 01 Deployment Manual (Compute Core)

This manual outlines the exact steps to deploy the containerized Node 01 architecture into the GCP Assured Workloads environment using **Direct VPC Egress**.

## Step 1: Provision the Assured Workloads Artifact Registry
Docker images must reside strictly within the designated regulatory boundary.

```bash
gcloud artifacts repositories create shtiya-os-registry \
    --repository-format=docker \
    --location=us-central1 \
    --description="HIPAA-compliant Docker registry for Shtiya OS Node 01" \
    --project=shtiya-os-assured-workloads
```

## Step 2: Build and Push the Container
Using Google Cloud Build ensures the compilation process remains internal.

```bash
gcloud builds submit \
    --tag us-central1-docker.pkg.dev/shtiya-os-assured-workloads/shtiya-os-registry/node-01:v1.8.4 \
    --project=shtiya-os-assured-workloads
```

## Step 3: Identity and Access Management (IAM) Configuration
The principle of least privilege is absolute. The Cloud Run service requires a dedicated Service Account.

```bash
# 3.1 Create the strict service account
gcloud iam service-accounts create node-01-sa \
    --display-name="Node 01 Application Core Identity" \
    --project=shtiya-os-assured-workloads

# 3.2 Grant Cloud SQL Client Role 
gcloud projects add-iam-policy-binding shtiya-os-assured-workloads \
    --member="serviceAccount:node-01-sa@shtiya-os-assured-workloads.iam.gserviceaccount.com" \
    --role="roles/cloudsql.client"

# 3.3 Grant Cloud SQL Instance User Role 
gcloud projects add-iam-policy-binding shtiya-os-assured-workloads \
    --member="serviceAccount:node-01-sa@shtiya-os-assured-workloads.iam.gserviceaccount.com" \
    --role="roles/cloudsql.instanceUser"

# 3.4 Grant Vertex AI User Role
gcloud projects add-iam-policy-binding shtiya-os-assured-workloads \
    --member="serviceAccount:node-01-sa@shtiya-os-assured-workloads.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"
```

## Step 4: The Direct VPC Egress Cloud Run Deployment
Crucially, the flag `--vpc-egress=private-ranges-only` forces the container to route traffic mapped to internal CIDR blocks directly through the internal VPC.

```bash
gcloud run deploy node-01-core \
    --image us-central1-docker.pkg.dev/shtiya-os-assured-workloads/shtiya-os-registry/node-01:v1.8.4 \
    --region=us-central1 \
    --project=shtiya-os-assured-workloads \
    --service-account=node-01-sa@shtiya-os-assured-workloads.iam.gserviceaccount.com \
    --network=shtiya-vpc \
    --subnet=shtiya-private-subnet \
    --vpc-egress=private-ranges-only \
    --allow-unauthenticated \
    --set-env-vars="INSTANCE_CONNECTION_NAME=shtiya-os-assured-workloads:us-central1:shtiya-db-05,DB_IAM_USER=node-01-sa@shtiya-os-assured-workloads.iam,REDIS_HOST=10.0.0.5" \
    --min-instances=3 \
    --max-instances=50
```

## Step 5: Database Privileges Initialization
Grant Data Manipulation Language (DML) rights strictly to the application identity inside Node 05.

```sql
-- Connect to Postgres as superuser and execute:
GRANT USAGE ON SCHEMA public TO "node-01-sa@shtiya-os-assured-workloads.iam";
GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, users, matters, case_embeddings, medical_chronologies TO "node-01-sa@shtiya-os-assured-workloads.iam";
```