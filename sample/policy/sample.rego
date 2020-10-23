package main

workload_resources := [
  "ReplicaSet",
  "Deployment",
  "DaemonSet",
  "StatefulSet",
  "Job",
]

deny[msg] {
  input.kind == workload_resources[_]
  not input.spec.selector.matchLabels.app

  msg := "Containers must provide app label for pod selectors"
}

deny[msg] {
  input.kind == workload_resources[_]
  not input.metadata.labels.app

  msg := sprintf("Deployments must provide app label [%v]", [input.metadata.labels])
}

deny[msg] {
  input.kind == workload_resources[_]
  not (input.spec.selector.matchLabels.app == input.spec.template.spec.metadata.labels.app)
  msg := sprintf("Containers must have same matchLabels matchLabels[%v] and metadata.labels[%v]", [input.spec.selector.matchLabels, input.spec.template.spec.metadata.labels])
}
