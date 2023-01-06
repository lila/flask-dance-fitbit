variable "feature_flags" {
  type        = string
  description = "A comma-seperated string of feature flags to enable specific terraform blocks."

  # TODO: Use Cookiecutter to replace this string.
  default = "gke,gke-ingress"
}

variable "env" {
  type    = string
  default = "dev"
}

variable "project_id" {
  type        = string
  description = "GCP Project ID"
  # TODO: Update below to your PROJECT_ID
  default = "solution1-373714"

  validation {
    condition     = length(var.project_id) > 0
    error_message = "The project_id value must be an non-empty string."
  }
}

variable "region" {
  type        = string
  description = "Default GCP region"
  default     = "us-central1"

  validation {
    condition     = length(var.region) > 0
    error_message = "The region value must be an non-empty string."
  }
}

variable "firestore_region" {
  type        = string
  description = "Firestore Region"
  default     = "us-central"
}

variable "bq_dataset_location" {
  type        = string
  description = "BigQuery Dataset location"
  default     = "US"
}

variable "storage_multiregion" {
  type    = string
  default = "us"
}

variable "admin_email" {
  type = string
  # TODO: replace with your own email
  default = "karanbhatia@google.com"
}

variable "api_domain" {
  type        = string
  description = "API endpoint domain, excluding protocol"
}

variable "web_app_domain" {
  type        = string
  description = "Web app domain, excluding protocol"
  default     = "localhost:8080"
}

variable "firebase_init" {
  type        = bool
  description = "Whether to initialize Firebase/Firestore."
  default     = false
}

variable "fitbit_oauth_client_id" {
  type        = string
  description = "fitbit webapi developer client id"
}

variable "fitbit_oauth_client_secret" {
  type        = string
  description = "fitbit webapi developer client secret"
}
