

resource "google_bigquery_dataset" "fitbit" {
  project     = var.project_id
  location    = var.region

  dataset_id  = "fitbit"
  description = "fitbit ingestion tables"
  
  labels = {
    goog-packaged-solution = "device-connect-for-fitbit"
  }

}