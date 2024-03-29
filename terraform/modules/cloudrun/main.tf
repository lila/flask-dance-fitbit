locals {
  allow_unauthenticated_flag = (var.allow_unauthenticated ? "--allow-unauthenticated" : "")
}

resource "google_artifact_registry_repository" "cloudrun_repository" {
  location      = var.region
  repository_id = var.repository_id
  description   = "Docker repository for CloudRun"
  format        = "DOCKER"
}

resource "google_cloud_run_service_iam_member" "member" {
  count    = (var.allow_unauthenticated ? 1 : 0)
  project  = var.project_id
  location = var.region
  service  = var.service_name
  role     = "roles/run.invoker"
  member   = "allUsers"

  depends_on = [time_sleep.wait_for_cloud_run_service]
}

resource "time_sleep" "wait_for_cloud_run_service" {
  create_duration = "30s"

  depends_on = [google_cloud_run_service.webapp]
}


# Creating a custom service account for cloud run
module "cloud-run-service-account" {
  source       = "github.com/terraform-google-modules/cloud-foundation-fabric/modules/iam-service-account/"
  project_id   = var.project_id
  name         = "cloudrun-sa"
  display_name = "This is service account for cloud run"

  iam = {
    "roles/iam.serviceAccountUser" = []
  }

  iam_project_roles = {
    (var.project_id) = [
      "roles/eventarc.eventReceiver",
      "roles/firebase.admin",
      "roles/firestore.serviceAgent",
      "roles/iam.serviceAccountUser",
      "roles/iam.serviceAccountTokenCreator",
      "roles/run.invoker",
      "roles/pubsub.serviceAgent",
    ]
  }
}

resource "null_resource" "deploy-cloudrun-image" {
  
  provisioner "local-exec" {
    working_dir = var.source_dir
    command = join(" ", [
      "gcloud builds submit",
      "--config=cloudbuild.yaml",
      join("", [
        "--substitutions=",
        join(",", [
          "_PROJECT_ID='${var.project_id}'",
          "_IMAGE='queue-image'",
          "_REGION='${var.region}'",
          "_REPOSITORY=${var.repository_id}"
        ])
      ])
    ])
  }
}

# Deploy image to Cloud Run
resource "google_cloud_run_service" "webapp" {
  # provider = google
  project  = var.project_id
  name     = var.service_name
  location = var.region
  template {
    spec {
        containers {
          image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_id}/queue-image"
          resources {
              limits = {
              "memory" = "1G"
              "cpu" = "1"
              }
          }
          dynamic "env" {
            for_each = var.env_vars
            content {
              name  = env.value["name"]
              value = env.value["value"]
            }
          }
        }
    }
    metadata {
        annotations = {
            "autoscaling.knative.dev/minScale" = "0"
            "autoscaling.knative.dev/maxScale" = "1"
        }
        labels = {
          goog-packaged-solution = "device-connect-for-fitbit"
        }
    }
  }
  traffic {
    percent = 100
    latest_revision = true
  }

  

  depends_on = [null_resource.deploy-cloudrun-image]
}


