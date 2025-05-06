
target "docker-metadata-action" {
context = "."
}
target "docker-platforms" {}

target "default" {
  inherits = ["docker-metadata-action", "docker-platforms"]
}