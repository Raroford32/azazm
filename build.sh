#!/bin/bash
# RDP NLA Checker Build Script
# Automated build and setup script for Ubuntu systems

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BUILD_TYPE=${BUILD_TYPE:-Release}
USE_DPDK=${USE_DPDK:-OFF}
INSTALL_PREFIX=${INSTALL_PREFIX:-/usr/local}
NUM_JOBS=${NUM_JOBS:-$(nproc)}

echo -e "${BLUE}RDP NLA Checker Build Script${NC}"
echo "=================================="
echo "Build type: $BUILD_TYPE"
echo "DPDK support: $USE_DPDK"
echo "Install prefix: $INSTALL_PREFIX"
echo "Parallel jobs: $NUM_JOBS"
echo ""

# Function to print colored messages
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root for system installation
check_root() {
    if [[ "$INSTALL_PREFIX" == "/usr/local" || "$INSTALL_PREFIX" == "/usr" ]]; then
        if [[ $EUID -ne 0 ]]; then
            print_error "System installation requires root privileges"
            echo "Run with sudo or set INSTALL_PREFIX to a user directory"
            exit 1
        fi
    fi
}

# Install system dependencies
install_dependencies() {
    print_status "Installing system dependencies..."
    
    # Update package list
    apt-get update
    
    # Essential build tools
    apt-get install -y \
        build-essential \
        cmake \
        pkg-config \
        git \
        wget \
        curl
    
    # Runtime dependencies
    apt-get install -y \
        libssl-dev \
        libgssapi-krb5-dev \
        libnuma-dev
    
    # Optional development tools
    apt-get install -y \
        clang-format \
        cppcheck \
        valgrind \
        gdb
    
    # DPDK dependencies (if requested)
    if [[ "$USE_DPDK" == "ON" ]]; then
        print_status "Installing DPDK dependencies..."
        apt-get install -y \
            meson \
            ninja-build \
            python3-pyelftools \
            libbsd-dev \
            libpcap-dev
    fi
    
    print_status "Dependencies installed successfully"
}

# Install DPDK from source
install_dpdk() {
    if [[ "$USE_DPDK" != "ON" ]]; then
        return 0
    fi
    
    print_status "Installing DPDK from source..."
    
    DPDK_VERSION="22.11.1"
    DPDK_DIR="/opt/dpdk"
    
    # Check if DPDK is already installed
    if pkg-config --exists libdpdk; then
        print_status "DPDK already installed, skipping..."
        return 0
    fi
    
    # Create DPDK directory
    mkdir -p "$DPDK_DIR"
    cd "$DPDK_DIR"
    
    # Download DPDK
    if [[ ! -f "dpdk-$DPDK_VERSION.tar.xz" ]]; then
        wget "https://fast.dpdk.org/rel/dpdk-$DPDK_VERSION.tar.xz"
    fi
    
    # Extract
    tar -xf "dpdk-$DPDK_VERSION.tar.xz"
    cd "dpdk-$DPDK_VERSION"
    
    # Configure
    meson build \
        --prefix="$INSTALL_PREFIX" \
        -Denable_kmods=true \
        -Ddisable_drivers=regex/* \
        -Denable_drivers=net/e1000,net/ixgbe,net/i40e,crypto/aesni_mb,crypto/qat
    
    # Build
    ninja -C build -j "$NUM_JOBS"
    
    # Install
    ninja -C build install
    
    # Update library cache
    ldconfig
    
    print_status "DPDK installed successfully"
}

# Setup hugepages
setup_hugepages() {
    if [[ "$USE_DPDK" != "ON" ]]; then
        return 0
    fi
    
    print_status "Setting up hugepages..."
    
    # Mount hugepages
    if ! mountpoint -q /mnt/huge; then
        mkdir -p /mnt/huge
        mount -t hugetlbfs nodev /mnt/huge
    fi
    
    # Allocate hugepages
    echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
    
    # Make persistent
    if ! grep -q "hugepages=512" /etc/default/grub; then
        print_warning "Add 'hugepages=512' to GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub"
        print_warning "Then run 'update-grub' and reboot for persistent hugepages"
    fi
    
    print_status "Hugepages configured"
}

# Build the project
build_project() {
    print_status "Building RDP NLA Checker..."
    
    # Create build directory
    mkdir -p build
    cd build
    
    # Configure
    cmake .. \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
        -DUSE_DPDK="$USE_DPDK" \
        -DBUILD_TESTS=ON \
        -DBUILD_BENCHMARKS=ON
    
    # Build
    make -j "$NUM_JOBS"
    
    # Run tests
    if [[ "$BUILD_TYPE" == "Debug" ]]; then
        print_status "Running tests..."
        make test || print_warning "Some tests failed"
    fi
    
    print_status "Build completed successfully"
}

# Install the project
install_project() {
    print_status "Installing RDP NLA Checker..."
    
    cd build
    make install
    
    # Create directories
    mkdir -p "$INSTALL_PREFIX/etc/rdp-checker"
    mkdir -p "$INSTALL_PREFIX/var/log/rdp-checker"
    
    # Set permissions
    if [[ "$INSTALL_PREFIX" == "/usr/local" || "$INSTALL_PREFIX" == "/usr" ]]; then
        # Create service user
        if ! id -u rdpchecker >/dev/null 2>&1; then
            useradd -r -s /bin/false -d /var/lib/rdp-checker rdpchecker
        fi
        
        # Set ownership
        chown -R rdpchecker:rdpchecker "$INSTALL_PREFIX/var/log/rdp-checker"
        
        # Install systemd service
        if [[ -d /etc/systemd/system ]]; then
            systemctl daemon-reload
            print_status "Systemd service installed. Enable with: systemctl enable rdp-checker"
        fi
    fi
    
    print_status "Installation completed"
}

# Setup DPDK environment
setup_dpdk_env() {
    if [[ "$USE_DPDK" != "ON" ]]; then
        return 0
    fi
    
    print_status "Setting up DPDK environment..."
    
    # Load kernel modules
    modprobe uio
    modprobe vfio-pci
    
    # Bind network interface (example)
    print_warning "Remember to bind your network interface to DPDK:"
    print_warning "  dpdk-devbind.py --status"
    print_warning "  dpdk-devbind.py --bind=vfio-pci 0000:XX:XX.X"
    
    print_status "DPDK environment setup completed"
}

# Performance tuning
tune_system() {
    print_status "Applying performance tuning..."
    
    # Increase file descriptor limits
    echo "* soft nofile 1000000" >> /etc/security/limits.conf
    echo "* hard nofile 1000000" >> /etc/security/limits.conf
    
    # Network tuning
    cat >> /etc/sysctl.conf << EOF
# RDP NLA Checker performance tuning
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 65536 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
EOF
    
    sysctl -p
    
    print_status "System tuning applied"
}

# Create example configuration
create_config() {
    print_status "Creating example configuration..."
    
    CONFIG_DIR="$INSTALL_PREFIX/etc/rdp-checker"
    
    # Main configuration
    cat > "$CONFIG_DIR/rdp-checker.conf" << EOF
# RDP NLA Checker Configuration

[general]
threads = 4
max_concurrent = 1000
timeout = 30
verbose = true

[dpdk]
enabled = false
port_id = 0
hardware_crypto = false

[tls]
ca_cert = 
client_cert = 
client_key = 

[performance]
cpu_affinity = false
hugepages = false
edge_triggered = true

[output]
json_output = false
results_file = /var/log/rdp-checker/results.log
EOF

    # Example targets
    cat > "$CONFIG_DIR/targets.txt" << EOF
# Target hosts (format: host:port)
192.168.1.100:3389
192.168.1.101:3389
10.0.0.50:3389
EOF

    # Example credentials
    cat > "$CONFIG_DIR/credentials.txt" << EOF
# Credentials (format: username:password:domain)
administrator:password:DOMAIN
admin:admin123:WORKGROUP
test:Test123!:
guest::
EOF

    print_status "Configuration files created in $CONFIG_DIR"
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    # Check binary
    if [[ -x "$INSTALL_PREFIX/bin/rdp_nla_checker" ]]; then
        print_status "Binary installed correctly"
    else
        print_error "Binary not found at $INSTALL_PREFIX/bin/rdp_nla_checker"
        exit 1
    fi
    
    # Test basic functionality
    if "$INSTALL_PREFIX/bin/rdp_nla_checker" --help >/dev/null 2>&1; then
        print_status "Basic functionality test passed"
    else
        print_error "Basic functionality test failed"
        exit 1
    fi
    
    # Check DPDK
    if [[ "$USE_DPDK" == "ON" ]]; then
        if pkg-config --exists libdpdk; then
            print_status "DPDK integration verified"
        else
            print_warning "DPDK integration issue"
        fi
    fi
    
    print_status "Installation verification completed"
}

# Main execution
main() {
    print_status "Starting RDP NLA Checker build process..."
    
    # Change to script directory
    cd "$(dirname "$0")"
    
    # Check prerequisites
    if [[ ! -f "CMakeLists.txt" ]]; then
        print_error "CMakeLists.txt not found. Run from project root directory."
        exit 1
    fi
    
    # Check root for system installation
    check_root
    
    # Install dependencies
    install_dependencies
    
    # Install DPDK if requested
    install_dpdk
    
    # Setup hugepages
    setup_hugepages
    
    # Build project
    build_project
    
    # Install project
    install_project
    
    # Setup DPDK environment
    setup_dpdk_env
    
    # Apply performance tuning
    tune_system
    
    # Create configuration
    create_config
    
    # Verify installation
    verify_installation
    
    print_status "RDP NLA Checker build and installation completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Edit configuration files in $INSTALL_PREFIX/etc/rdp-checker/"
    echo "2. Run: $INSTALL_PREFIX/bin/rdp_nla_checker --help"
    if [[ "$USE_DPDK" == "ON" ]]; then
        echo "3. Bind network interface to DPDK"
        echo "4. Reboot to enable hugepages (if not already done)"
    fi
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dpdk)
            USE_DPDK=ON
            shift
            ;;
        --debug)
            BUILD_TYPE=Debug
            shift
            ;;
        --prefix=*)
            INSTALL_PREFIX="${1#*=}"
            shift
            ;;
        --jobs=*)
            NUM_JOBS="${1#*=}"
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --dpdk           Enable DPDK support"
            echo "  --debug          Build in debug mode"
            echo "  --prefix=PATH    Installation prefix (default: /usr/local)"
            echo "  --jobs=N         Number of parallel build jobs (default: nproc)"
            echo "  --help           Show this help"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main
