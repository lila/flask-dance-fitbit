output "url" {
  value       = module.cloudrun-sample.url
  description = "url for the webapp."
}

output "container" {
  value       = module.cloudrun-sample.container
  description = "container for the webapp."
}