

resource "google_cloud_scheduler_job" "job" {
  project          = var.project_id
  region           = var.region

  name             = "test-job"
  description      = "test http job"
  schedule         = "*/8 * * * *"
  time_zone        = "America/New_York"
  attempt_deadline = "320s"

  retry_config {
    retry_count = 1
  }

  http_target {
    http_method = "GET"
    uri         = "${var.webapp_base_url}/allfitbitusers"
  }

  
}