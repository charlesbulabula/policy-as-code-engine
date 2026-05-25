package kubernetes.pod_security

import future.keywords.in

# Deny containers running as root
deny[msg] {
    container := input.request.object.spec.containers[_]
    sc := container.securityContext
    sc.runAsUser == 0
    msg := sprintf("Container '%s' must not run as root (runAsUser: 0)", [container.name])
}

deny[msg] {
    container := input.request.object.spec.containers[_]
    sc := container.securityContext
    not sc.runAsNonRoot == true
    not sc.runAsUser > 0
    msg := sprintf("Container '%s' must set runAsNonRoot: true or runAsUser > 0", [container.name])
}

# Deny privileged containers
deny[msg] {
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%s' must not run in privileged mode", [container.name])
}

# Deny missing resource limits
deny[msg] {
    container := input.request.object.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf("Container '%s' must define resources.limits.cpu", [container.name])
}

deny[msg] {
    container := input.request.object.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%s' must define resources.limits.memory", [container.name])
}

# Deny host networking / PID / IPC
deny[msg] {
    input.request.object.spec.hostNetwork == true
    msg := "Pod must not use host network (hostNetwork: true)"
}

deny[msg] {
    input.request.object.spec.hostPID == true
    msg := "Pod must not use host PID namespace (hostPID: true)"
}

deny[msg] {
    input.request.object.spec.hostIPC == true
    msg := "Pod must not use host IPC namespace (hostIPC: true)"
}

# Deny :latest image tag
deny[msg] {
    container := input.request.object.spec.containers[_]
    image := container.image
    endswith(image, ":latest")
    msg := sprintf("Container '%s' must not use 'latest' image tag (image: %s)", [container.name, image])
}

deny[msg] {
    container := input.request.object.spec.containers[_]
    image := container.image
    not contains(image, ":")
    msg := sprintf("Container '%s' must specify an explicit image tag (image: %s)", [container.name, image])
}

# Deny privilege escalation
deny[msg] {
    container := input.request.object.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("Container '%s' must not allow privilege escalation", [container.name])
}

# _r 20260522113912-1e1f1e6e
