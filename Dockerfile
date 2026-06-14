# PROBLEM 5: old base image with known vulnerabilities.
# Trivy should flag CRITICAL/HIGH issues coming from this old image.
# We use an old, pinned tag on purpose so the scanner has real findings.
# We do NOT run pip install here, so the build stays fast and reliable and
# Trivy is the thing that flags the problem (not a build error).
FROM python:3.9.0-slim

WORKDIR /app
COPY . .

CMD ["python", "app.py"]
