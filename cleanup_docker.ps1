# cleanup_docker.ps1
# This script forcefully removes all stopped/dead SageMath Docker containers used by the MCP server to prevent massive disk bloat.
# Execute this periodically or when disk space runs low.

Write-Host "Cleaning up orphaned sagemath/sagemath containers..."
$containers = docker ps -aq --filter "ancestor=sagemath/sagemath"
if ($containers) {
    docker rm -f $containers
    Write-Host "Cleanup complete."
} else {
    Write-Host "No orphaned SageMath containers found."
}
docker system df
