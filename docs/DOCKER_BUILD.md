# Docker build validation

## Recorded failure boundary

On October 9, 2026, [main CI run 37993212614](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/37993212614), Docker job 114033388917, failed while resolving `python:3.11-slim`: Docker Hub returned HTTP 429. [PR 121 CI run 37994335824](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/37994335824), Docker job 114040836865, timed out while pulling `moby/buildkit:buildx-stable-1` from Docker Hub. Neither recorded failure demonstrates a failing application test or defective runtime image; both happened before application build execution.

## Ordinary CI mitigation

The Docker gate uses the hosted runner's `docker` driver, avoiding a separate BuildKit container pull. GitHub Actions cache export is omitted because the Docker driver requires the containerd image store to support that cache backend; this workflow does not configure it. CI selects the Docker Official Python image through its public ECR mirror with `PYTHON_BASE_IMAGE`. The Dockerfile's default remains `python:3.11-slim` for existing build commands. Mirror and upstream tag availability are external dependencies; mutable tags do not guarantee identical future builds.

Docker documents [automatic publication of Docker Official Images to public ECR](https://www.docker.com/blog/news-from-aws-reinvent-docker-official-images-on-amazon-ecr-public/). The [Python gallery entry](https://gallery.ecr.aws/docker/library/python) identifies the publisher. Docker documents [driver cache requirements](https://docs.docker.com/build/cache/backends/gha/).

After the builder's test gate and wheel installation, CI starts the final image with a local dummy key and `--network none`. It probes `/v1/ready` from inside the container and removes the temporary container on exit. The dummy WAL and audit paths point inside the image-owned `/var/lib/mcp` directory, so readiness checks its directory permissions under the non-root runtime user. No host ports or persistent mounts are configured. Readiness returns HTTP 503 when either directory is missing or unwritable, and HTTP 200 when both checks pass. It does not measure security effectiveness or integration delivery.

## Verification boundary

The repair was checked locally with the 11 Dockerfile structure tests, helper lint/format checks, the offline recruiter demo invariants, YAML parsing, and Bash syntax validation. The exact mirror tag returned HTTP 200 during a registry manifest HEAD request, with manifest digest `sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce`. A local Docker build was unavailable because this workspace has no Docker executable. At commit `0c912037d06130e004a3a22b6147c2b97af102bc`, [hosted CI run 37999099427](https://github.com/poojakira/mcp-agent-security-gateway/actions/runs/37999099427) completed all 15 reported checks successfully. Docker job 114053394857 built the final image and passed the isolated `/v1/health` smoke. That verifies the registry mitigation and image startup at the cited commit. The subsequent review correction changes the probe to `/v1/ready` and explicit disposable WAL/audit paths; its hosted result is pending and is not implied by the earlier health-check pass. No deployment, external delivery, persistent identity or baseline operation is part of this validation.
