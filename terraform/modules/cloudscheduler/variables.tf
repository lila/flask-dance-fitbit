variable "project_id" {
  type        = string
  description = "project ID"
}

variable "region" {
  type        = string
  description = "GCP region"
}

variable "webapp_base_url" {
  type        = string
  description = "base url for the deployed cloudrun webapp"
}