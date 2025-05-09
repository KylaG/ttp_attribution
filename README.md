# MITRE ATT&CK Threat Actor Attribution System

This repository contains a novel threat actor attribution system that leverages the MITRE ATT&CK framework to identify potential threat actors behind cyber attacks based on their techniques, tactics, and procedures (TTPs).

Google Drive Link with files (threat intelligence dataset, TTP embedding files, and example outputs): https://drive.google.com/drive/folders/1spjdXx_rCO6I1b4g_5X2C6ksJwlFN6Gu?usp=drive_link

## Overview

This system analyzes cyber threat reports and attributes them to known threat actors by:

1. Extracting MITRE ATT&CK techniques mentioned in threat reports using semantic search
2. Comparing these techniques to known threat actor behavior patterns
3. Using a Bayesian approach to calculate attribution probabilities
4. Evaluating performance through k-fold cross-validation

The system includes a standard version and an enhanced version using HyDE (Hypothetical Document Embeddings) to improve attribution accuracy.

## Key Features

- **Semantic Search**: Uses OpenAI embeddings to match threat report text to MITRE ATT&CK techniques
- **HyDE Enhancement**: Generates hypothetical threat report paragraphs to improve technique extraction
- **Parallel Processing**: Leverages concurrent execution for efficient processing
- **Cross-Validation**: Includes k-fold validation to ensure robust performance
- **Prior Probabilities**: Incorporates threat actor prevalence data to improve attribution

## Repository Structure

### Main Scripts

- `everything.py` - Standard threat actor attribution system using basic embeddings. Processes threat reports to extract MITRE techniques and attributes them to threat actors using Bayesian analysis.
- `everythingHYDE.py` - Enhanced version using HyDE (Hypothetical Document Embeddings). Generates hypothetical threat report paragraphs for each MITRE technique to improve semantic matching accuracy.
- `find_threat_actors.py` - Web scraper that visits the MITRE ATT&CK website to identify well-documented threat groups (those with 10+ references).
- `rid_technique.py` - Preprocessing script that prioritizes subtechniques over parent techniques to avoid redundancy in the MITRE dataset.

### Individual Files in Root Directory

#### Example Threat Reports

- `APT41_threat.txt` - FireEye report about APT41's global intrusion campaign using multiple exploits (Citrix, Cisco, Zoho)
- `Sandworm.txt` - CISA advisory about Sandworm's "Infamous Chisel" Android malware campaign

#### Data Files

- `threat_actor_weights.csv` - CSV mapping threat actors to their commonly used MITRE techniques with frequency weights
- `best_validation.csv` - Best model weights from cross-validation, containing P(technique | threat actor) probabilities
- `single_test_result.csv` - Example attribution results showing threat actor attribution performance

#### (in Google Drive) Pre-Computed Embedding Files

- `saved_embeddings.npz` - Cached embeddings of MITRE technique descriptions
- `pruned_hyde_embeddings.npz` - HyDE-enhanced embeddings for MITRE techniques
- `pruned_no_hyde_embeddings.npz` - Standard embeddings without HyDE enhancement

### Directories

#### (in Google Drive) TTP_definitions/

Contains MITRE ATT&CK technique definitions and processed data:

- `raw_terms.txt` - Original scraped MITRE technique data
- `processed_techniques.txt` - Cleaned MITRE technique descriptions
- `processed_techniques_pruned.txt` - Techniques with parent/child redundancy removed
- `processed_subtechniques_pruned.txt` - Final processed subtechniques used by the system
- `pruned_csv_for_hyde.csv` - CSV format of techniques for HyDE processing
- `saved_embeddings_full.npz` - Complete embeddings for all techniques

#### (in Google Drive) threat_actors_added_data/

Dataset containing 728 threat intelligence reports across 29 threat actors:

| Threat Actor      | File Count | Description                                            |
| ----------------- | ---------- | ------------------------------------------------------ |
| Ajax              | 13         | Reports on RocketKitten and related Iranian operations |
| APT3              | 11         | Chinese threat actor targeting various sectors         |
| APT17             | 16         | Chinese DeputyDog group operations                     |
| APT28             | 75         | Russian GRU Fancy Bear operations                      |
| APT29             | 71         | Russian SVR Cozy Bear operations                       |
| APT32             | 16         | Vietnamese OceanLotus group                            |
| APT33             | 11         | Iranian Elfin/Magnallium operations                    |
| APT39             | 12         | Iranian Chafer group activities                        |
| Cobalt Group      | 17         | Financial sector targeting group                       |
| DeepPanda         | 10         | Chinese group targeting think tanks                    |
| DragonFly         | 18         | Russian energy sector operations                       |
| FIN6              | 20         | Financial fraud and ransomware group                   |
| FIN7              | 40         | Carbanak/Navigator financial crimes                    |
| Gamaredon Group   | 11         | Russian FSB operations in Ukraine                      |
| Kimsuky           | 17         | North Korean reconnaissance operations                 |
| Lazarus Group     | 82         | North Korean state operations                          |
| Magic Hound       | 25         | Iranian APT35/Charming Kitten                          |
| menuPass          | 26         | Chinese Stone Panda operations                         |
| MuddyWater        | 17         | Iranian espionage operations                           |
| OilRig            | 45         | Iranian APT34 operations                               |
| Sandworm          | 36         | Russian GRU destructive operations                     |
| TA505             | 16         | Cybercrime group behind Dridex                         |
| TeamTNT           | 11         | Cryptojacking operations                               |
| Threat Group-3390 | 13         | Chinese Emissary Panda                                 |
| Tonto Team        | 10         | Chinese CactusPete operations                          |
| Tropic Trooper    | 10         | Chinese KeyBoy operations                              |
| Turla             | 49         | Russian FSB Snake operations                           |
| Winnti Group      | 11         | Chinese supply chain operations                        |
| Wizard Spider     | 18         | Russian cybercrime TrickBot/Ryuk                       |

#### (in Google Drive) example_outputs/

Contains example outputs from different experimental configurations:

- `HYDE_GPT4/` - Results using GPT-4 for HyDE hypothesis generation
- `HYDE_P(A)_mult/` - Results with HyDE and prior probability multiplication
- `NoHYDE_P(A)_mult/` - Results without HyDE but with prior probabilities
- `first_full_HYDE/` - Initial full HyDE implementation results
- `sliding_window_take1/` - Results from sliding window text processing approach

## How the Main Scripts Work

### everything.py (Standard Attribution)

1. Loads MITRE ATT&CK data from `TTP_definitions/processed_subtechniques_pruned.txt`
2. Creates embeddings using OpenAI's text-embedding-3-large model
3. Processes threat reports in 3-line batches to extract techniques
4. Uses semantic search with cosine similarity to find relevant techniques
5. Builds probabilistic model with k-fold cross-validation
6. Calculates P(technique | threat actor) for attribution
7. Outputs results to validation CSV files

### everythingHYDE.py (HyDE-Enhanced Attribution)

1. For each MITRE technique, generates 5 hypothetical threat report paragraphs using GPT-4
2. Creates blended embeddings combining original descriptions and hypotheticals
3. Uses higher confidence threshold (0.65) for technique extraction
4. Incorporates prior probabilities based on threat actor document counts
5. Multiplies attribution scores by prior probabilities
6. Achieves improved attribution accuracy over standard method

## Key Algorithm Components

- **Semantic Search**: Finds MITRE techniques in threat reports using cosine similarity
- **Bayesian Attribution**: P(threat actor | techniques) using conditional probabilities
- **HyDE Implementation**: Generates 5 hypothetical scenarios per technique
- **K-fold Validation**: Uses 70/20/10 train/validate/test splits
- **Parallel Processing**: Concurrent file processing for efficiency

## Usage

### Basic Attribution

```python
python everything.py
```

### HyDE-Enhanced Attribution

```python
python everythingHYDE.py
```

### Find Well-Documented Threat Actors

```python
python find_threat_actors.py
```

### Preprocess MITRE Techniques

```python
python rid_technique.py
```

## Requirements

- Python 3.x
- pandas
- numpy
- openai (with API key)
- tqdm
- pypdf
- requests
- BeautifulSoup4
- concurrent.futures

## Performance Metrics

The system evaluates attribution accuracy by calculating the average rank of the correct threat actor in the sorted prediction list. Lower ranks indicate better performance (1 being a perfect match).

## Data Sources

- MITRE ATT&CK framework (https://attack.mitre.org/)
- Thailand CERT (ThaiCERT) threat intelligence reports

## Future Improvements

- Expand the threat actor dataset
- Implement additional embedding models
- Add support for real-time threat report analysis
- Integrate with threat intelligence platforms
- Improve the HyDE prompt engineering

## Citation

If you use this system in your research, please cite:

```
K. Guru, R. J. Moss, and M. J. Kochenderfer, "On technique identification and threat-actor attribution using LLMs and embedding models," 2025.

```

## License

This work is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License.

To view a copy of this license, visit http://creativecommons.org/licenses/by-nc/4.0/ or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

Copyright (c) 2025 Kyla Guru, Robert J. Moss, Mykel J. Kochenderfer

## Contact

Kyla Guru

- Email: kylaguru@stanford.edu, kylaguru@gmail.com
- Twitter: @GuruDetective
- Affiliation: Computer Science, Stanford University

Robert J. Moss

- Email: mossr@cs.stanford.edu
- Affiliation: Computer Science, Stanford University

Mykel J. Kochenderfer

- Email: mykel@stanford.edu
- Affiliation: Aeronautics and Astronautics, Stanford University

For questions about this research, please contact the authors directly.
For technical issues with the code, please open an issue in this repository.
