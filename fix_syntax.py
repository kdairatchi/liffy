#!/usr/bin/env python3

import re

# Read the core.py file
with open('core.py', 'r') as f:
    content = f.read()

# Fix print statements with syntax errors
# Pattern: print(t.red("..."))(variable)
# Replace with: print(t.red("...") + str(variable))
pattern = r'print\(t\.red\(([^)]+)\)\)\(([^)]+)\)'
replacement = r'print(t.red(\1) + str(\2))'
content = re.sub(pattern, replacement, content)

# Fix missing closing parentheses in print statements
# Pattern: print(t.red("...") + "text"
# Replace with: print(t.red("...") + "text")
pattern2 = r'print\(t\.red\(([^)]+)\) \+ "([^"]+)"'
replacement2 = r'print(t.red("\1\2"))'
content = re.sub(pattern2, replacement2, content)

# Write the fixed content back
with open('core.py', 'w') as f:
    f.write(content)

print("Fixed syntax errors in core.py")