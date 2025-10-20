# Liffy Ultimate Unified - Makefile
# Complete LFI Exploitation & Vulnerability Testing Tool

.PHONY: all install setup build run test clean help

# Default target
all: setup

# Installation and setup
install: setup
	@echo "🚀 Installing Liffy Ultimate Unified..."

setup:
	@echo "📦 Setting up Liffy Ultimate Unified..."
	@chmod +x liffy_ultimate_unified.py
	@chmod +x random
	@mkdir -p ~/targets/scope
	@echo "✅ Setup complete!"

# Build Go tools
build:
	@echo "🔨 Building Go tools..."
	@go install github.com/Anon-Exploiter/sqry@latest
	@go install github.com/bp0lr/gauplus@latest
	@go install github.com/ferreiraklet/airixss@latest
	@go install github.com/ferreiraklet/jeeves@latest
	@go install github.com/tomnomnom/qsreplace@latest
	@go install github.com/tomnomnom/gf@latest
	@echo "✅ Go tools built successfully!"

# Run examples
run:
	@echo "🎯 Running Liffy Ultimate Unified examples..."
	@echo "Single target mode:"
	@echo "  make run-single"
	@echo "Random targets mode:"
	@echo "  make run-random"
	@echo "Domain testing mode:"
	@echo "  make run-domain"

run-single:
	@echo "🎯 Running single target mode..."
	@python3 liffy_ultimate_unified.py --url "http://example.com/file.php?page=" --data --auto-ip --auto-port

run-random:
	@echo "🎯 Running random targets mode..."
	@python3 liffy_ultimate_unified.py --random --test-mode all --auto-ip --auto-port

run-domain:
	@echo "🎯 Running domain testing mode..."
	@python3 liffy_ultimate_unified.py --domain example.com --test-mode lfi --auto-ip --auto-port

# Test the installation
test:
	@echo "🧪 Testing Liffy Ultimate Unified..."
	@python3 liffy_ultimate_unified.py --help
	@echo "✅ Test passed!"

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	@rm -f *.log
	@rm -f liffy_*_results_*.json
	@rm -f /tmp/*.php
	@rm -f /tmp/xss_results_*.txt
	@echo "✅ Cleanup complete!"

# Help
help:
	@echo "Liffy Ultimate Unified - Makefile Commands"
	@echo "=========================================="
	@echo ""
	@echo "Setup & Installation:"
	@echo "  make setup     - Set up the environment and permissions"
	@echo "  make install   - Install and set up everything"
	@echo "  make build     - Build Go tools (sqry, gauplus, airixss, jeeves, qsreplace, gf)"
	@echo ""
	@echo "Running:"
	@echo "  make run       - Show run examples"
	@echo "  make run-single - Run single target mode"
	@echo "  make run-random - Run random targets mode"
	@echo "  make run-domain - Run domain testing mode"
	@echo ""
	@echo "Testing & Maintenance:"
	@echo "  make test      - Test the installation"
	@echo "  make clean     - Clean up temporary files"
	@echo "  make help      - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  # Quick start with random targets"
	@echo "  make run-random"
	@echo ""
	@echo "  # Test specific domain"
	@echo "  make run-domain"
	@echo ""
	@echo "  # Full setup and test"
	@echo "  make install && make test"

# Quick start targets
quick-start: setup build
	@echo "🚀 Quick start complete! Run 'make run-random' to test with random targets"

# Development targets
dev-setup: setup build
	@echo "🔧 Development setup complete!"

# Production targets
prod-setup: setup build
	@echo "🏭 Production setup complete!"
	@echo "Ready for deployment!"