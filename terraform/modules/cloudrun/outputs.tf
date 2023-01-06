output "url" {
    value       = google_cloud_run_service.webapp.status[0].url
    description = "url for the webapp"
}

output "container" {
    value       = "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_id}/queue-image"
    description = "the webapp container reference"
}