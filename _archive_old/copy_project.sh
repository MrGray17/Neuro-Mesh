#!/bin/bash

# Define the output file name
OUTPUT="neuro_mesh_full_code.txt"

# Clear the output file if it exists
> "$OUTPUT"

echo "===============================================" >> "$OUTPUT"
echo "  NEURO-MESH SOURCE CODE DUMP - $(date)       " >> "$OUTPUT"
echo "===============================================" >> "$OUTPUT"

# Find and append every relevant source file
# We exclude binaries, object files, and the venv folder
find . -maxdepth 3 -not -path '*/.*' -not -path './venv*' -not -path './node_modules*' -not -path './obj*' -not -path './bin*' -type f \( -name "*.cpp" -o -name "*.hpp" -o -name "*.c" -o -name "*.h" -o -name "*.py" -o -name "*.jsx" -o -name "*.js" -o -name "Makefile" -o -name "*.sh" \) | while read -r file; do
    echo -e "\n\n--- FILE: $file ---" >> "$OUTPUT"
    cat "$file" >> "$OUTPUT"
done

# Copy the content to the system clipboard
if command -v xclip > /dev/null; then
    cat "$OUTPUT" | xclip -selection clipboard
    echo "✅ Success: All code copied to clipboard via xclip."
elif command -v pbcopy > /dev/null; then
    cat "$OUTPUT" | pbcopy
    echo "✅ Success: All code copied to clipboard via pbcopy."
else
    echo "❌ Error: No clipboard utility found. Code saved to $OUTPUT instead."
fi

# Clean up
rm "$OUTPUT"
