#!/bin/bash
# Setup script for Liffy Enhanced Ultimate features

echo "🚀 Setting up Liffy Enhanced Ultimate features..."

# Install Go tools
echo "📦 Installing Go tools..."

# Install gauplus
echo "Installing gauplus..."
go install github.com/bp0lr/gauplus@latest

# Install GF
echo "Installing GF..."
go install github.com/tomnomnom/gf@latest

# Install GF patterns
echo "Installing GF patterns..."
go install github.com/1ndianl33t/Gf-Patterns@latest

# Install QSReplace
echo "Installing QSReplace..."
go install github.com/tomnomnom/qsreplace@latest

# Install airixss
echo "Installing airixss..."
go install github.com/ferreiraklet/airixss@latest

# Install jeeves
echo "Installing jeeves..."
go install github.com/ferreiraklet/jeeves@latest

# Install sqry
echo "Installing sqry..."
go install github.com/ferreiraklet/sqry@latest

# Setup GF patterns
echo "🔧 Setting up GF patterns..."
mkdir -p ~/.gf
cp -r $GOPATH/src/github.com/1ndianl33t/Gf-Patterns/* ~/.gf/

# Create scope directory
echo "📁 Creating scope directory..."
mkdir -p ~/targets/scope

# Create example scope files
echo "📝 Creating example scope files..."
cat > ~/targets/scope/inscope.txt << 'SCOPE_EOF'
# Example in-scope targets
example.com
*.example.com
test.example.com
SCOPE_EOF

cat > ~/targets/scope/priority_inscope.txt << 'PRIORITY_EOF'
# Priority in-scope targets
critical.example.com
admin.example.com
api.example.com
PRIORITY_EOF

# Make scripts executable
echo "🔐 Making scripts executable..."
chmod +x liffy_enhanced_ultimate.py
chmod +x url_gatherer.py

echo "✅ Setup complete!"
echo ""
echo "Usage examples:"
echo "  # Comprehensive testing"
echo "  python3 liffy_enhanced_ultimate.py --domain example.com --comprehensive --test-mode all"
echo ""
echo "  # Subdomain enumeration"
echo "  python3 liffy_enhanced_ultimate.py --domain example.com --subdomains --test-mode lfi"
echo ""
echo "  # GF pattern discovery"
echo "  python3 liffy_enhanced_ultimate.py --domain example.com --gf-patterns lfi xss sqli --test-mode all"
echo ""
echo "  # QSReplace testing"
echo "  python3 liffy_enhanced_ultimate.py --domain example.com --qsreplace --test-mode all"
echo ""
echo "  # Random targets"
echo "  python3 liffy_enhanced_ultimate.py --random --comprehensive --test-mode all"
