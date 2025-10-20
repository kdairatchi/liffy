#!/usr/bin/env python3

# Read the file
with open('core.py', 'r') as f:
    content = f.read()

# Fix all the problematic print statements
import re

# Pattern 1: print(t.red("...") + str(variable))
pattern1 = r'print\(t\.red\("([^"]+)" \+ str\(([^)]+)\)\)'
replacement1 = r'print(t.red("\1") + str(\2))'
content = re.sub(pattern1, replacement1, content)

# Pattern 2: print(t.red("...") + str(variable))
pattern2 = r'print\(t\.red\("([^"]+)" \+ str\(([^)]+)\)\)'
replacement2 = r'print(t.red("\1") + str(\2))'
content = re.sub(pattern2, replacement2, content)

# Write the fixed content
with open('core.py', 'w') as f:
    f.write(content)

print("Fixed all syntax errors")