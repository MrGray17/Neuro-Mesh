#!/bin/bash

# Define the final output file
OUTPUT="neuro_mesh_full_dump.txt"

# Clear the output file if it already exists
> "$OUTPUT"

echo "========================================================" >> "$OUTPUT"
echo "  NEURO-MESH : COMPLETE CODEBASE ARCHIVE               " >> "$OUTPUT"
echo "  GENERATED: $(date)                                   " >> "$OUTPUT"
echo "  PROJECT LEAD: El Yazid Hammoubel                     " >> "$OUTPUT"
echo "========================================================" >> "$OUTPUT"

# Define the file types we care about based on our architecture
# We exclude: .git, venv, node_modules, obj, and bin folders
find . -maxdepth 4 \
    -not -path '*/.*' \
    -not -path './venv*' \
    -not -path './node_modules*' \
    -not -path './obj*' \
    -not -path './bin*' \
    -type f \( \
    -name "*.cpp" -o \
    -name "*.hpp" -o \
    -name "*.c" -o \
    -name "*.h" -o \
    -name "*.py" -o \
    -name "*.jsx" -o \
    -name "*.js" -o \
    -name "*.css" -o \
    -name "Makefile" -o \
    -name "*.sh" -o \
    -name ".env" \
    \) | sort | while read -r file; do
        echo -e "\n\nFILE_PATH: $file" >> "$OUTPUT"
        echo "--------------------------------------------------------" >> "$OUTPUT"
        cat "$file" >> "$OUTPUT"
        echo -e "\n--------------------------------------------------------" >> "$OUTPUT"
done

echo "✅ Success: Full codebase compiled into $OUTPUT"
