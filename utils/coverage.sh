# Make sure this script is executable. On Unix based systems, run "chmod +x coverage.sh".
# To run this script, type "./coverage.sh".

#!/bin/bash

set -e # exit on error

# check if lcov is installed, if not, execute installation
if ! command -v lcov &>/dev/null; then
    echo "lcov is not installed. Installing..."
	# check if its macos or linux.
	if [ "$(uname)" == "Darwin" ]; then
		brew install lcov
        
	else
		sudo apt-get install lcov
	fi
fi
lcov --version

# generates lcov.info
FOUNDRY_PROFILE=coverage forge coverage --report lcov

# Generate summary
lcov \
    --rc branch_coverage=1 \
    --ignore-errors inconsistent \
    --list lcov.info

# Open more granular breakdown in browser
genhtml \
    --rc branch_coverage=1 \
    --output-directory coverage \
    --ignore-errors category \
    --ignore-errors inconsistent \
    --ignore-errors corrupt \
    --ignore-errors empty \
    --ignore-errors missing \
    lcov.info

open coverage/index.html