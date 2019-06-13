workflow "Test and Coverage" {
  on = "push"
  resolves = ["go"]
}

action "go" {
  uses = "./ci"
}
