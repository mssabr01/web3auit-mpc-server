#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="web3audit-mpc"
REGISTRY="ghcr.io"
DATE_TAG=$(date +%Y-%m-%d)

echo -e "${GREEN}=== Web3 Audit MCP - Offline Image Builder ===${NC}\n"

# Check if username is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Error: GitHub username required${NC}"
    echo "Usage: $0 <github-username>"
    echo "Example: $0 yourusername"
    exit 1
fi

USERNAME=$1
FULL_IMAGE="${REGISTRY}/${USERNAME}/${IMAGE_NAME}"

# Step 1: Build
echo -e "${YELLOW}[1/5] Building offline image...${NC}"
docker build -t ${IMAGE_NAME}:offline .

# Step 2: Tag
echo -e "${YELLOW}[2/5] Tagging images...${NC}"
docker tag ${IMAGE_NAME}:offline ${FULL_IMAGE}:latest
docker tag ${IMAGE_NAME}:offline ${FULL_IMAGE}:${DATE_TAG}
echo "  ✓ Tagged as ${FULL_IMAGE}:latest"
echo "  ✓ Tagged as ${FULL_IMAGE}:${DATE_TAG}"

# Step 3: Verify
echo -e "${YELLOW}[3/5] Verifying image works without network...${NC}"
if docker run --network=none --rm ${IMAGE_NAME}:offline sh -c "solc --version && slither --version" > /dev/null 2>&1; then
    echo "  ✓ Image works offline"
else
    echo -e "${RED}  ✗ Image verification failed${NC}"
    exit 1
fi

# Step 4: Size check
echo -e "${YELLOW}[4/5] Image size:${NC}"
docker images ${IMAGE_NAME}:offline --format "  {{.Repository}}:{{.Tag}} - {{.Size}}"

# Step 5: Push prompt
echo -e "${YELLOW}[5/5] Ready to push to registry${NC}"
echo ""
echo "To push to GitHub Container Registry:"
echo ""
echo "  1. Authenticate:"
echo "     echo \$GITHUB_TOKEN | docker login ${REGISTRY} -u ${USERNAME} --password-stdin"
echo ""
echo "  2. Make package public (after first push):"
echo "     Go to: https://github.com/users/${USERNAME}/packages/container/${IMAGE_NAME}/settings"
echo ""
echo "  3. Push images:"
echo "     docker push ${FULL_IMAGE}:latest"
echo "     docker push ${FULL_IMAGE}:${DATE_TAG}"
echo ""
echo "  4. Pull and run offline:"
echo "     docker run --network=none -v \$(pwd)/contracts:/contracts ${FULL_IMAGE}:latest"
echo ""

# Optional: Auto-push if GITHUB_TOKEN is set
if [ -n "${GITHUB_TOKEN:-}" ]; then
    read -p "GITHUB_TOKEN detected. Push now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Pushing images..."
        echo $GITHUB_TOKEN | docker login ${REGISTRY} -u ${USERNAME} --password-stdin
        docker push ${FULL_IMAGE}:latest
        docker push ${FULL_IMAGE}:${DATE_TAG}

        echo -e "${GREEN}✓ Successfully pushed images${NC}"
        echo ""
        echo "Image digest:"
        docker inspect ${FULL_IMAGE}:latest --format='{{index .RepoDigests 0}}'
    fi
fi

echo -e "${GREEN}Done!${NC}"
