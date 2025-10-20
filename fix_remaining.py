#!/usr/bin/env python3

# Read the file
with open('core.py', 'r') as f:
    lines = f.readlines()

# Fix all the problematic print statements
for i, line in enumerate(lines):
    if 'print(t.red(' in line and '))(' in line and ')' in line:
        # Extract the parts
        if 'HTTP Error' in line:
            lines[i] = line.replace('))(access_error)', ') + str(access_error))')
            lines[i] = lines[i].replace('))(filter_error)', ') + str(filter_error))')
        elif 'Process Error' in line:
            lines[i] = line.replace('))(os_error)', ') + str(os_error))')
        elif 'Unknown Error' in line:
            lines[i] = line.replace('))(unknown_error)', ') + str(unknown_error))')
        else:
            lines[i] = line.replace('))(os_error)', ') + str(os_error))')

# Write the fixed file
with open('core.py', 'w') as f:
    f.writelines(lines)

print("Fixed remaining syntax errors")