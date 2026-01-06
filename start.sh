#!/bin/bash
# =============================================================================
# GigaChad GRC - One-Command Start
# =============================================================================
#
# USAGE:
#   ./start.sh         Start all services
#   ./start.sh stop    Stop all services
#   ./start.sh logs    View logs
#   ./start.sh status  Check service status
#
# REQUIREMENTS:
#   - Docker Desktop installed and running
#
# =============================================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_banner() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                               ║${NC}"
    echo -e "${CYAN}║   ${BOLD}🏋️ GigaChad GRC${NC}${CYAN}                                              ║${NC}"
    echo -e "${CYAN}║                                                               ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker is not installed.${NC}"
        echo ""
        echo "Please install Docker Desktop:"
        echo "  https://www.docker.com/products/docker-desktop"
        echo ""
        exit 1
    fi

    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}❌ Docker is not running.${NC}"
        echo ""
        echo "Please start Docker Desktop and try again."
        echo ""
        exit 1
    fi
}

start_services() {
    print_banner
    check_docker

    echo -e "${BLUE}Starting GigaChad GRC...${NC}"
    echo ""
    echo "This may take a few minutes on first run while Docker builds the images."
    echo ""

    # Start all services
    docker compose up -d --build

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}║   ${BOLD}🎉 GigaChad GRC is Starting!${NC}${GREEN}                                ║${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}Access Points:${NC}"
    echo -e "   ${CYAN}Frontend${NC}        http://localhost:3000"
    echo -e "   ${CYAN}API Docs${NC}        http://localhost:3001/api/docs"
    echo -e "   ${CYAN}Keycloak${NC}        http://localhost:8080 (admin/admin)"
    echo -e "   ${CYAN}Grafana${NC}         http://localhost:3003 (admin/admin)"
    echo ""
    echo -e "${BOLD}How to Login:${NC}"
    echo -e "   1. Go to ${CYAN}http://localhost:3000${NC}"
    echo -e "   2. Click the ${CYAN}\"Dev Login\"${NC} button"
    echo -e "   3. You're in! No password needed."
    echo ""
    echo -e "${YELLOW}Note:${NC} First startup takes 2-3 minutes for database initialization."
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "   ${CYAN}./start.sh stop${NC}    Stop all services"
    echo -e "   ${CYAN}./start.sh logs${NC}    View logs"
    echo -e "   ${CYAN}./start.sh status${NC}  Check service status"
    echo ""

    # Open browser on macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "${YELLOW}Opening browser in 10 seconds...${NC}"
        (sleep 10 && open http://localhost:3000 2>/dev/null) &
    fi
}

stop_services() {
    print_banner
    echo -e "${YELLOW}Stopping GigaChad GRC...${NC}"
    docker compose down
    echo -e "${GREEN}✓ All services stopped${NC}"
    echo ""
}

show_logs() {
    docker compose logs -f
}

show_status() {
    print_banner
    echo -e "${BOLD}Service Status:${NC}"
    echo ""
    docker compose ps
    echo ""
}

# Main
case "${1:-start}" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    logs)
        show_logs
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: ./start.sh [start|stop|logs|status]"
        echo ""
        echo "Commands:"
        echo "  start   Start all services (default)"
        echo "  stop    Stop all services"
        echo "  logs    View service logs"
        echo "  status  Check service status"
        exit 1
        ;;
esac








