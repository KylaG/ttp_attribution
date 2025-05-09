"""
MITRE ATT&CK Threat Group References Scraper

This script scrapes the MITRE ATT&CK website (https://attack.mitre.org/groups/) 
to identify well-documented threat actor groups. It counts the number of external 
references/citations for each threat group and filters for those with at least 10 
references, which indicates they are well-studied groups with significant research.

The script:
1. Scrapes the main MITRE ATT&CK groups directory page
2. For each threat group, visits their dedicated page
3. Parses the references section to count external citations
4. Outputs a list of well-documented groups with their reference counts

This information is useful for cybersecurity research, threat intelligence analysis,
and for building datasets of well-studied threat actors.

Requirements:
- requests
- BeautifulSoup4
"""

import requests
from bs4 import BeautifulSoup

def count_references(group_url):
    """
    Extracts and counts the number of external references for a specific threat group.
    
    This function scrapes a MITRE ATT&CK group page to determine how many external
    references or citations exist for the group. These references typically link to
    research reports, blog posts, or other documentation about the threat group's
    activities.
    
    Args:
        group_url (str): The full URL to a MITRE ATT&CK group page
                        (e.g., 'https://attack.mitre.org/groups/G0007/')
    
    Returns:
        int: The total number of external references found for the threat group
    
    Notes:
        - The function parses the HTML structure of the references section
        - It specifically looks for links with class 'external text' within ordered lists
        - The references section is identified by an h2 tag with id 'references'
    """
    response = requests.get(group_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    # Find the references section based on the provided structure.
    references_section = soup.find('h2', id='references').find_next('div', class_='row')
    # Find all divs with class 'col' within the references section.
    cols = references_section.find_all('div', class_='col')
    links = []
    for col in cols:
        # Find the ordered list within each column div.
        for references_list in col.find_all('ol'):
            # Extract all links from the list items within each ordered list.
            links.extend([a['href'] for a in references_list.find_all('a', class_='external text')])
    return len(links)

def main():
    """
    Main function that scrapes the MITRE ATT&CK website to find threat groups with
    at least 10 external references.
    
    This function:
    1. Fetches the main MITRE ATT&CK groups page
    2. Extracts links to all individual threat group pages
    3. Visits each group page to count its external references
    4. Filters for groups with 10 or more references
    5. Prints the results to the console
    
    The output includes the group name, reference count, and URL for each qualifying group.
    
    Returns:
        None: Results are printed directly to the console
    """
    url = 'https://attack.mitre.org/groups/'
    print(url)
    response = requests.get(url)
    print(response)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all links to the group pages
    table = soup.find('table', class_='table-bordered')
    groups = [tr.find('td').find('a') for tr in table.find_all('tr')[1:]] if table else []

    # print(groups)
    # List to hold groups with >= 10 references
    groups_with_many_references = []

    for group in groups:
        group_url = f"https://attack.mitre.org{group['href']}"
        #print(group_url)
        num_references = count_references(group_url)
        #print(num_references)

        if num_references >= 10:
            group_name = group.text.strip()
            groups_with_many_references.append((group_name, num_references, group_url))

    for group_name, num_references, group_url in groups_with_many_references:
        print(f"{group_name} has {num_references} references found at {group_url}")

if __name__ == "__main__":
    """
    Script entry point that calls the main function when the script is executed directly.
    
    This conditional block ensures the script only runs when executed as a standalone program
    and not when imported as a module in another script.
    """
    print("I'm here")
    main()