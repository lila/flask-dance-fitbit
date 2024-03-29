# project-specific locals
locals {
  services = [
    "appengine.googleapis.com",            # AppEngine
    "artifactregistry.googleapis.com",     # Artifact Registry
    "bigquery.googleapis.com",             # BigQuery
    "bigquerydatatransfer.googleapis.com", # BigQuery Data Transfer
    "cloudbuild.googleapis.com",           # Cloud Build
    "compute.googleapis.com",              # Load Balancers, Cloud Armor
    "container.googleapis.com",            # Google Kubernetes Engine
    "containerregistry.googleapis.com",    # Google Container Registry
    "dataflow.googleapis.com",             # Cloud Dataflow
    "firebase.googleapis.com",             # Firebase
    "firestore.googleapis.com",            # Firestore
    "iam.googleapis.com",                  # Cloud IAM
    "logging.googleapis.com",              # Cloud Logging
    "monitoring.googleapis.com",           # Cloud Operations Suite
    "run.googleapis.com",                  # Cloud Run
    "secretmanager.googleapis.com",        # Secret Manager
    "storage.googleapis.com",              # Cloud Storage
    "cloudscheduler.googleapis.com",       # Cloud Scheduler
  ]
}

data "google_project" "project" {}

module "project_services" {
  source     = "../../modules/project_services"
  project_id = var.project_id
  services   = local.services
}

module "service_accounts" {
  depends_on     = [module.project_services]
  source         = "../../modules/service_accounts"
  project_id     = var.project_id
  env            = var.env
  project_number = data.google_project.project.number
}

module "firebase" {
  depends_on       = [module.project_services]
  source           = "../../modules/firebase"
  project_id       = var.project_id
  firestore_region = var.firestore_region
  firebase_init    = var.firebase_init
}

module "vpc_network" {
  source      = "../../modules/vpc_network"
  project_id  = var.project_id
  vpc_network = "default-vpc"
  region      = var.region

  depends_on = [ module.project_services ]
}

# Deploy sample-service to CloudRun
# Uncomment below to enable deploying microservices with CloudRun.
module "cloudrun-sample" {
  depends_on = [module.project_services, module.vpc_network]

  source                = "../../modules/cloudrun"
  project_id            = var.project_id
  region                = var.region
  source_dir            = "../../.."
  service_name          = "fitbit-flask-test"
  repository_id         = "cloudrun"
  allow_unauthenticated = true
  env_vars              = [
                            { name = "FITBIT_OAUTH_CLIENT_ID", value = var.fitbit_oauth_client_id },
                            { name = "FITBIT_OAUTH_CLIENT_SECRET", value = var.fitbit_oauth_client_secret }
                          ]
}

module "bigquery" {
  source                = "../../modules/bigquery"
  project_id            = var.project_id
  region                = var.region
}

module "cloudscheduler" {
  depends_on = [ module.cloudrun-sample ]

  source                = "../../modules/cloudscheduler"
  project_id            = var.project_id
  region                = var.region
  webapp_base_url       = module.cloudrun-sample.url
}

