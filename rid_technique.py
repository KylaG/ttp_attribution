"""
MITRE ATT&CK Technique Pruning Script

This script processes a file containing MITRE ATT&CK techniques and subtechniques to 
create a pruned version that prioritizes subtechniques over their parent techniques.

When both a parent technique (e.g., T1234) and its subtechniques (e.g., T1234.001) 
are present, the script removes the parent technique and keeps only the subtechniques. 
This helps avoid redundancy when using techniques for attribution, as subtechniques 
provide more specific information about threat actor behavior.

The script:
1. Reads a file containing MITRE ATT&CK techniques and subtechniques
2. Identifies parent techniques and their subtechniques using regex pattern matching
3. When subtechniques are present, removes their parent techniques
4. Writes the pruned list to a new file in sorted order

This preprocessing step improves the quality of the dataset for threat actor attribution
by ensuring that the most specific technique descriptions are used.
"""

import re

def prune_techniques(input_file, output_file):
    """
    Processes a file of MITRE ATT&CK techniques to prioritize subtechniques over parent techniques.
    
    This function reads an input file containing MITRE ATT&CK techniques and their descriptions,
    identifies parent-child relationships, and removes parent techniques when subtechniques exist.
    The resulting pruned list is written to an output file in sorted order.
    
    Args:
        input_file (str): Path to the input file containing techniques
        output_file (str): Path where the pruned output will be written
    
    Example:
        If the input file contains both T1234 (parent) and T1234.001 (subtechnique),
        only T1234.001 will be included in the output file.
    """
    # Read the input file
    with open(input_file, 'r') as file:
        lines = file.readlines()

    # Dictionary to store techniques and their descriptions
    techniques = {}

    # Regular expression to find techniques and subtechniques
    pattern = re.compile(r"(T\d{4}(?:\.\d{3})?)\s+")

    # Collect all techniques and subtechniques
    for line in lines:
        match = pattern.search(line)
        if match:
            technique_id = match.group(1)
            # Check if the key exists, and if it is a subtechnique, remove the parent
            if '.' in technique_id:
                parent_id = technique_id.split('.')[0]
                if parent_id in techniques:
                    del techniques[parent_id]
            # Add technique to dictionary
            techniques[technique_id] = line

    # Write the pruned techniques to an output file
    with open(output_file, 'w') as file:
        for technique in sorted(techniques):
            file.write(techniques[technique])

# Usage example
prune_techniques('processed_techniques_pruned.txt', 'processed_subtechniques_pruned.txt')