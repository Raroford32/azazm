# RDP NLA (CredSSP) Login Credentials Checker

## Project Overview

This project implements a high-performance RDP NLA (Network Level Authentication) credentials checker using CredSSP (Credential Security Support Provider) protocol. It supports both DPDK kernel-bypass for maximum throughput (50,000+ handshakes/sec) and an epoll+OpenSSL fallback for standard systems (16,000-18,000 handshakes/sec).

## Architecture

The implementation consists of several key components:

1. **Main Checker Engine** (`rdp_nla_checker.c`) - Core orchestration and worker management
2. **CredSSP Implementation** (`credsp.c`) - MS-CredSSP protocol implementation with ASN.1 encoding/decoding
3. **DPDK Implementation** (`dpdk_impl.c`) - High-performance kernel-bypass networking with hardware crypto offload
4. **Configuration Management** - Support for targets, credentials, and performance tuning options

## Features

### Performance Paths
- **DPDK Mode**: Kernel-bypass networking with SmartNIC/DPU hardware crypto offload
- **epoll Mode**: High-performance userspace implementation with OpenSSL

### Protocol Support
- MS-CredSSP v2 protocol implementation
- NTLM and Kerberos authentication mechanisms
- ASN.1 DER encoding/decoding for TSRequest/TSResponse messages
- TLS 1.2+ for secure transport

### Performance Optimizations
- Multi-threaded worker architecture
- CPU affinity and hugepage support
- Edge-triggered epoll for minimal overhead
- Connection pooling and buffer reuse
- Hardware crypto acceleration

## Build Requirements

### System Dependencies
```bash
# Ubuntu 22.04 LTS packages
sudo apt-get update
sudo apt-get install -y build-essential libnuma-dev meson ninja-build
sudo apt-get install -y libssl-dev libgssapi-krb5-dev
sudo apt-get install -y pkg-config cmake
```

### DPDK (Optional)
```bash
# Clone and build DPDK
git clone https://github.com/DPDK/dpdk.git
cd dpdk
meson build -Denable_kmods=true
ninja -C build
sudo ninja -C build install
```

### Hugepages Configuration
```bash
# Add to /etc/default/grub:
# GRUB_CMDLINE_LINUX_DEFAULT="default_hugepagesz=2M hugepagesz=2M hugepages=512"
sudo update-grub
sudo reboot

# Mount hugepages
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
```

## Building

### Standard Build (epoll+OpenSSL)
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### DPDK Build
```bash
mkdir build && cd build
cmake -DUSE_DPDK=ON ..
make -j$(nproc)
```

### Optimized Build
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-O3 -march=native" ..
make -j$(nproc)
strip rdp_nla_checker
```

## Usage

### Basic Usage
```bash
# Run with default settings (epoll mode)
./rdp_nla_checker

# Run with DPDK kernel-bypass
./rdp_nla_checker --dpdk

# Specify number of threads and concurrent connections
./rdp_nla_checker --threads 8 --concurrent 5000

# Set timeout
./rdp_nla_checker --timeout 60
```

### Configuration Files

#### Targets File (targets.txt)
```
192.168.1.100:3389
192.168.1.101:3389
10.0.0.50:3389
```

#### Credentials File (credentials.txt)
```
administrator:password:DOMAIN
admin:admin123:WORKGROUP
test:Test123!:
guest::
```

### Advanced Usage
```bash
# Load targets and credentials from files
./rdp_nla_checker --targets targets.txt --credentials credentials.txt

# Enable verbose output and JSON results
./rdp_nla_checker --verbose --json-output results.json

# Use specific TLS certificates
./rdp_nla_checker --ca-cert ca.pem --client-cert client.pem --client-key client.key

# Enable CPU affinity and hugepages
./rdp_nla_checker --cpu-affinity --hugepages
```

## Performance Tuning

### System Limits
```bash
# Increase file descriptor limits
ulimit -n 1000000
echo "* soft nofile 1000000" >> /etc/security/limits.conf
echo "* hard nofile 1000000" >> /etc/security/limits.conf

# Adjust kernel parameters
echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65535" >> /etc/sysctl.conf
sysctl -p
```

### DPDK Setup
```bash
# Bind NIC to DPDK
sudo dpdk-devbind.py --status
sudo dpdk-devbind.py --bind=vfio-pci 0000:02:00.0

# Load VFIO module
sudo modprobe vfio-pci
```

### CPU Isolation
```bash
# Isolate CPU cores for DPDK (add to /etc/default/grub)
GRUB_CMDLINE_LINUX_DEFAULT="isolcpus=2-15 nohz_full=2-15 rcu_nocbs=2-15"
```

## Benchmarking

### TLS Handshake Performance
```bash
# Test pure TLS handshake performance
./rdp_nla_checker --benchmark-tls --duration 60

# Test with tls-perf tool
git clone https://github.com/tempesta-tech/tls-perf.git
cd tls-perf && make
./tls-perf -c 1000 -t 60 192.168.1.100:3389
```

### DPDK Crypto Performance
```bash
# Test crypto PMD throughput
dpdk-test-crypto-perf -l 0-3 -- --devtype crypto_aesni_mb --optype cipher-then-auth
```

### Memory Usage
```bash
# Monitor memory and CPU usage
top -p $(pgrep rdp_nla_checker)
htop
perf top -p $(pgrep rdp_nla_checker)
```

## Output Format

### Standard Output
```
RDP NLA Checker initialized with 4 threads
Mode: epoll+OpenSSL
Targets: 2, Credentials: 3
Worker 0 started
Worker 1 started
Connection 192.168.1.100:3389 - SUCCESS (0.142s)
Connection 192.168.1.101:3389 - FAILED (0.089s)

=== RDP NLA Checker Statistics ===
Total attempts: 1000
Successful auths: 250
Failed auths: 600
Timeouts: 100
Errors: 50
Duration: 45.23 seconds
Handshakes per second: 22.11
Average handshake time: 0.095 ms
Average auth time: 0.187 ms
==================================
```

### JSON Output
```json
{
  "summary": {
    "total_attempts": 1000,
    "successful_auths": 250,
    "failed_auths": 600,
    "timeouts": 100,
    "errors": 50,
    "duration": 45.23,
    "handshakes_per_second": 22.11,
    "avg_handshake_time": 0.095,
    "avg_auth_time": 0.187
  },
  "results": [
    {
      "target": "192.168.1.100:3389",
      "username": "administrator",
      "domain": "DOMAIN",
      "result": "SUCCESS",
      "duration": 0.142,
      "timestamp": "2025-06-29T10:30:45Z"
    }
  ]
}
```

## Deployment

### Systemd Service
```ini
[Unit]
Description=RDP NLA Checker
After=network.target

[Service]
Type=forking
User=rdpchecker
Group=rdpchecker
ExecStart=/usr/local/bin/rdp_nla_checker --daemon --config /etc/rdp-checker/config.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Docker Container
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libssl3 libgssapi-krb5-2 \
    && rm -rf /var/lib/apt/lists/*

COPY rdp_nla_checker /usr/local/bin/
COPY configs/ /etc/rdp-checker/

EXPOSE 8080
CMD ["/usr/local/bin/rdp_nla_checker", "--api-server", "--port", "8080"]
```

### Monitoring
```bash
# Expose metrics endpoint
./rdp_nla_checker --metrics-port 9090

# Prometheus scraping
curl http://localhost:9090/metrics
```

## Security Considerations

- Use TLS client certificates for mutual authentication
- Implement rate limiting to prevent abuse
- Run with minimal privileges (dedicated user account)
- Monitor for suspicious authentication patterns
- Regularly rotate test credentials

## Troubleshooting

### Common Issues

1. **DPDK Initialization Fails**
   ```bash
   # Check hugepage allocation
   cat /proc/meminfo | grep Huge
   
   # Verify NIC binding
   dpdk-devbind.py --status
   ```

2. **High Memory Usage**
   ```bash
   # Reduce concurrent connections
   ./rdp_nla_checker --concurrent 1000
   
   # Monitor with valgrind
   valgrind --tool=memcheck ./rdp_nla_checker
   ```

3. **Low Performance**
   ```bash
   # Check CPU affinity
   taskset -pc $(pgrep rdp_nla_checker)
   
   # Enable performance governor
   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## References

- [MS-CredSSP Protocol Specification](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-credssp/)
- [DPDK Documentation](https://doc.dpdk.org/)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [RFC 4559 - SPNEGO](https://tools.ietf.org/html/rfc4559)
# azazm
