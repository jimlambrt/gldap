#!/bin/bash

# Check if the file exists
if [ ! -f "$1" ]; then
    echo "File not found!"
    exit 1
fi

# Read the last two lines of the file and extract the last columns
last_col_last_line=$(tail -n 1 "$1" | awk -F',' '{print $NF}')
last_col_second_last_line=$(tail -n 2 "$1" | head -n 1 | awk -F',' '{print $NF}')

# Compare the last columns
if [ "$last_col_last_line" = "$last_col_second_last_line" ]; then
    exit 0
else
    echo "coverage has changed."
    echo "generate a new report and badge using: make coverage"
    echo "and then check-in the new report and badge?"
    echo "coverage before: $last_col_second_last_line"
    echo "coverage now: $last_col_last_line"
    exit 1
fi