#!/bin/bash
# ==============================================================================
# SHTIYA OS: REPOSITORY AUDIT UTILITY
# ==============================================================================
echo "Top 20 largest files currently tracked by Git:"
echo "------------------------------------------------"
git ls-tree -r -l --long HEAD | sort -k 4 -n -r | head -n 20