workflow "Test and Coverage" {
  on = "push"
  resolves = ["go"]
}

action "go" {
  uses = "./ci"
  secrets = ["CODECOV_TOKEN"]
}
