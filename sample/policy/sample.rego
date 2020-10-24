package main

workload_resources := [
  "ReplicaSet",
  "Deployment",
  "DaemonSet",
  "StatefulSet",
  "Job",
]

deny[msg] {
  input[_].contents.kind == workload_resources[_]
  file := input[_].contents
  not file.spec.selector.matchLabels.app

  msg := "Containers must provide app label for pod selectors"
}

deny[msg] {
  input[_].contents.kind == workload_resources[_]
  file := input[_].contents
  not file.metadata.labels.app

  msg := sprintf("Deployments must provide app label [%v]", [file.metadata.labels])
}

deny[msg] {
  input[_].contents.kind == workload_resources[_]
  file := input[_].contents
  not (file.spec.selector.matchLabels.app == file.spec.template.spec.metadata.labels.app)
  msg := sprintf("Containers must have same matchLabels matchLabels[%v] and metadata.labels[%v]", [file.spec.selector.matchLabels, file.spec.template.spec.metadata.labels])
}
