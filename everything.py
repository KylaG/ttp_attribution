"""
MITRE ATT&CK Threat Actor Attribution System

This system analyzes cyber threat reports and attributes them to known threat actors
based on the MITRE ATT&CK framework. It uses vector embeddings and semantic search
to identify which attack techniques (TTPs) are described in a report, then compares
these techniques to known threat actor behavior patterns.

The system:
1. Processes MITRE ATT&CK technique descriptions into vector embeddings
2. Extracts techniques mentioned in threat reports using semantic search
3. Builds a probabilistic model based on known threat actor behavior
4. Uses a Bayesian approach to calculate attribution probabilities 
5. Evaluates performance through k-fold cross-validation

This approach allows for automated, evidence-based attribution of cyber attacks
to specific threat actors based on their technique usage patterns. It can help
security analysts quickly identify potential threat actors behind new attacks by
matching behavioral signatures.

Requirements:
- pandas
- numpy
- openai
- tqdm
- pypdf
- concurrent.futures
"""


import pandas as pd
from openai import OpenAI
from tqdm import tqdm
import numpy as np
from pypdf import PdfReader
from collections import Counter
import os
import random
import json
import copy
import math
import concurrent.futures

mode = "dev"

# Create OpenAI Client
client = OpenAI(
    api_key="XXXXXX",
    organization='XXXXXX',
)

def get_data():
    """
    Loads and preprocesses MITRE ATT&CK data from a tab-separated file.
    
    This function reads technique/subtechnique data from a TSV file, then transforms the IDs
    to properly associate subtechniques with their parent techniques. For example, a subtechnique
    '.001' will be combined with its parent technique ID 'T1234' to form 'T1234.001'.
    
    Returns:
        DataFrame: Processed DataFrame containing MITRE ATT&CK technique information
    """
    df = pd.read_csv("processed_subtechniques_pruned.txt", sep="\t")
    print("Raw MITRE terms scraped from https://attack.mitre.org/techniques/enterprise/")
    print(df.head(20))
    print()
    print("Total number of MITRE terms: ", len(df))
    print("____________________\n")

    id_col = list(df["ID"])
    name_col = list(df["Name"])

    transformed_id_col = [id_col[0]]
    transformed_name_col = [name_col[0]]

    latest_t_id = id_col[0]
    latest_prefix_name = name_col[0]

    for id, name in zip(id_col[1:], name_col[1:]):
        if "T" in id:
            latest_t_id = id
            new_id = id
            latest_prefix_name = name
            new_name = name
        else:
            new_id = latest_t_id + id
            new_name = name
        transformed_id_col.append(new_id)
        transformed_name_col.append(new_name)

    df["ID"] = transformed_id_col
    df["Name"] = transformed_name_col
    print(df.head(20))
    return df

def create_embeddings(df):
    """
    Creates vector embeddings for MITRE ATT&CK technique descriptions using OpenAI's embedding model.
    
    This function processes each technique description in the dataframe and generates
    embeddings using OpenAI's text-embedding-3-large model. These embeddings are then
    saved to a .npz file for future use.
    
    Args:
        df (DataFrame): DataFrame containing MITRE ATT&CK technique information
    
    Returns:
        numpy.ndarray: Matrix of embeddings for the technique descriptions
    """
    # Convert DataFrame to a list of dictionaries
    list_of_dicts = df.to_dict('records')
    embeddings = []

    print("Creating embeddings...")
    for dict in tqdm(list_of_dicts):
        response = client.embeddings.create(
            input=dict["Description"],
            model="text-embedding-3-large"
        )
        embedding = response.data[0].embedding
        embeddings.append(embedding)
    print("Created")

    # Convert to a NumPy matrix
    matrix = np.array(embeddings)

    # Save the matrix into a .npz file
    np.savez("pruned_no_hyde_embeddings.npz", matrix=matrix)

    return matrix

def load_embeddings_matrix():
    """
    Loads the pre-computed embeddings matrix from a saved .npz file.
    
    This function is used to avoid recalculating embeddings when the program
    is run multiple times, improving efficiency.
    
    Returns:
        numpy.ndarray: Matrix of embeddings for the technique descriptions
    """
    # Load the .npz file
    #loaded_data = np.load('saved_embeddings.npz')
    loaded_data = np.load('pruned_no_hyde_embeddings.npz')   

    # Extract the matrix
    loaded_matrix = loaded_data['matrix']

    return loaded_matrix

def search(embeddings_matrix, reference_df, query_str, topk=5):
    """
    Performs semantic search to find MITRE techniques relevant to a given query.
    
    This function embeds the input query string, then calculates cosine similarity
    between the query embedding and all technique embeddings to find the most 
    semantically similar techniques.
    
    Args:
        embeddings_matrix (numpy.ndarray): Matrix of embeddings for all techniques
        reference_df (DataFrame): DataFrame containing MITRE technique information
        query_str (str): The input text to search for related techniques
        topk (int, optional): Number of top results to return. Defaults to 5.
    
    Returns:
        DataFrame: Top k most similar techniques to the query
    """
    response = client.embeddings.create(
            input=query_str,
            model="text-embedding-3-large"
    )
    query_embedding = response.data[0].embedding

    scores = np.matmul(embeddings_matrix, query_embedding)
    reference_df["scores"] = [score * 100 for score in scores]
    
    # Find the indices of the top k values
    indices = np.argsort(scores)[-topk:][::-1]

    return reference_df.iloc[indices]

def get_txt_data(file_path):
    """
    Processes a text file by grouping lines into sets of three.
    
    This function reads a file and groups every three consecutive lines into
    a single entry, allowing processing of structured text data where related 
    information spans multiple lines.
    
    Args:
        file_path (str): Path to the text file to process
    
    Returns:
        list: List of strings, where each string contains three lines from the original file
    """
    # Initialize an empty list to hold the grouped lines
    grouped_lines = []

    # Open and read the file
    with open(file_path, 'r') as file:
        # Temporary list to store chunks of 3 lines
        temp_lines = []
        
        for line in file:
            # Strip newline characters and add to the temporary list
            temp_lines.append(line.strip())
            
            # Check if we have collected 3 lines
            if len(temp_lines) == 3:
                # Join the 3 lines into a single string and add to the final list
                grouped_lines.append('\n'.join(temp_lines))
                # Reset the temporary list for the next group of 3 lines
                temp_lines = []
                # temp_lines.pop(0)
        
        # Check for any remaining lines that didn't make up a full group of 3
        if temp_lines:
            grouped_lines.append('\n'.join(temp_lines))

    # Now, `grouped_lines` contains your data, where each element is 3 lines from the file
    return grouped_lines

def get_hardcoded_threat_actor_weights(normalize=False):
    """
    Loads and processes threat actor technique usage data from a CSV file.
    
    This function reads a CSV containing information about which techniques are
    used by different threat actors and their relative usage frequencies. Optionally,
    the weights can be normalized to reduce bias toward threat actors that use a
    variety of techniques.
    
    Args:
        normalize (bool, optional): Whether to normalize weights so they sum to 1 for each actor. 
                                    Defaults to False.
    
    Returns:
        list: List of dictionaries mapping technique names to their usage weights for each threat actor
    """
    df = pd.read_csv("threat_actor_weights.csv", sep=",")
    list_of_dicts = df.to_dict(orient='records')
    # normalize by making sure each row (which corresponds to a threat actor) sums to 1
    # reduces bias towards threat actors who use a variety of techniques
    for dict in list_of_dicts:
        sum = 0
        for key in dict:
            if key != "Cyber Threat Group":
                sum += dict[key]
        if sum == 0:
            sum = 1 # only relevant for admin@338 row, avoids a divide by zero error
        for key in dict:
            if key != "Cyber Threat Group":
                if normalize:
                    dict[key] = dict[key] / sum
    df = pd.DataFrame(list_of_dicts)
    return list_of_dicts

def get_term_counts(txt_file, embeddings_matrix, reference_df, normalize=False):
    """
    Analyzes a text file to identify and count relevant MITRE ATT&CK techniques.
    
    This function processes a text file (likely a threat report) by splitting it into
    batches and using semantic search to identify the most relevant MITRE techniques
    in each batch. It then counts the occurrences of each technique across the entire document.
    
    Args:
        txt_file (str): Path to the text file to analyze
        embeddings_matrix (numpy.ndarray): Matrix of embeddings for all techniques
        reference_df (DataFrame): DataFrame containing MITRE technique information
        normalize (bool, optional): Whether to normalize the term counts to sum to 1. Defaults to False.
    
    Returns:
        dict: Dictionary mapping technique names to their counts or normalized frequencies
    """
    text_batches = get_txt_data(file_path=txt_file)
    all_relevant_terms = []
    # for text_batch in tqdm(text_batches):
    for text_batch in text_batches:
        relevant_mitre_terms_df = search(embeddings_matrix=embeddings_matrix, reference_df=reference_df, query_str=text_batch, topk=5)
        relevant_mitre_terms = list(relevant_mitre_terms_df["Name"])
        all_relevant_terms = all_relevant_terms + relevant_mitre_terms
    # print(f"Processed {len(text_batches)}")
    # Use Counter to count occurrences
    term_counts = Counter(all_relevant_terms)
    term_counts = dict(term_counts)
    sorted_dict = dict(sorted(term_counts.items(), key=lambda item: item[1], reverse=True))
    # for key, val in sorted_dict.items():
    #     print(f"{key} : {val}")
    # normalize the term counts to be between 0 and 1
    sum_value = sum(term_counts.values())
    if normalize:
        normalized_term_counts = {key: val / sum_value for key, val in term_counts.items()}
        return normalized_term_counts
    else:
        return term_counts

def calculate_scores(normalized_term_counts, all_threat_actor_weights):
    """
    Calculates similarity scores between a document and known threat actors.
    
    This function compares the techniques identified in a document with the 
    technique usage patterns of known threat actors to determine which actors
    are most similar to the behavior described in the document.
    
    Args:
        normalized_term_counts (dict): Dictionary mapping technique names to their normalized frequencies
        all_threat_actor_weights (list): List of dictionaries mapping technique names to weights for each actor
    
    Returns:
        DataFrame: Sorted DataFrame with threat actors and their similarity scores
    """
    # all_threat_actors -> list of dicts where one key is called 'Cyber Threat Group' and maps to a str and the other keys (which are MITRE codes) maps to floats
    # normalized_term_counts -> dict where each key is a MITRE term and each val is a float
    scores_df = [] # will be a list of dicts
    for threat_actor_weights in all_threat_actor_weights:
        # weights for one threat actor
        score = 0
        for mitre_code in normalized_term_counts.keys():
            if mitre_code in threat_actor_weights.keys():
                score += threat_actor_weights[mitre_code] * normalized_term_counts[mitre_code]
        scores_df.append({"Cyber Threat Group" : threat_actor_weights["Cyber Threat Group"], "Score" : score})
    scores_df = pd.DataFrame(scores_df)
    scores_df = scores_df.groupby('Cyber Threat Group', as_index=False).mean()
    scores_df = scores_df.sort_values(by='Score', ascending=False)
    return scores_df

def list_non_hidden_files(path):
    """
    Lists all non-hidden files in a directory.
    
    Args:
        path (str): Directory path to search
    
    Returns:
        list: List of non-hidden file names in the directory
    """
    # List all entries in the given path
    entries = os.listdir(path)
    
    # Filter out hidden files and only keep non-hidden files
    non_hidden_files = [entry for entry in entries if not entry.startswith('.') and os.path.isfile(os.path.join(path, entry))]
    
    return non_hidden_files

def list_non_hidden_directories(path):
    """
    Lists all non-hidden directories in a directory.
    
    Args:
        path (str): Directory path to search
    
    Returns:
        list: List of non-hidden directory names
    """
    # List all entries in the given path
    entries = os.listdir(path)
    
    # Filter out hidden files and only keep non-hidden files
    non_hidden_dirs = [entry for entry in entries if not entry.startswith('.')]
    
    return non_hidden_dirs

def add_term_counts(a, b):
    """
    Combines two dictionaries of term counts by adding values for shared keys.
    
    Args:
        a (dict): First dictionary of term counts
        b (dict): Second dictionary of term counts
    
    Returns:
        dict: Combined dictionary with summed values
    """
    for key, b_val in b.items():
        if key in a.keys():
            a[key] = a[key] + b_val
        else:
            a[key] = b_val
    return a

def generate_threat_actor_splits(strings, k, train, valid, test):
    """
    Generates k-fold cross-validation splits for a list of files.
    
    This function creates k different train/validation/test splits of the input files,
    respecting the specified proportions for each set.
    
    Args:
        strings (list): List of file names to split
        k (int): Number of splits to generate
        train (float): Proportion of data for training (0-1)
        valid (float): Proportion of data for validation (0-1)
        test (float): Proportion of data for testing (0-1)
    
    Returns:
        list: List of tuples, where each tuple contains (train_files, valid_files, test_files)
    """
    assert math.isclose(train + valid + test, 1.0)
    assert train > 0
    assert valid > 0
    assert test > 0
    length = len(strings)
    train_size = round(train * length)
    valid_size = round(valid * length)

    splits = []

    for _ in range(k):
        # Shuffle the list to ensure randomness
        random.shuffle(strings)

        # Create the splits based on the calculated sizes
        train = strings[:train_size]
        valid = strings[train_size:train_size + valid_size]
        test = strings[train_size + valid_size:]

        splits.append((train, valid, test))

    # gets rid of splits that have train valid or test empty
    splits = [split for split in splits if (len(split[0]) > 0 and len(split[1]) > 0 and len(split[2]) > 0)]

    # die (potentially)
    assert len(splits) == k

    return splits

def generate_splits(k=3):
    """
    Generates k-fold cross-validation splits for all threat actors.
    
    This function creates k different train/validation/test splits for each
    threat actor's data files, resulting in a dictionary mapping each threat
    actor to its k splits.
    
    Args:
        k (int, optional): Number of splits to generate. Defaults to 3.
    
    Returns:
        dict: Dictionary mapping threat actor names to their respective k splits
    """
    all_splits = {}
    for threat_actor in list_non_hidden_directories("threat_actors_added_data"):
        txt_file_names = list_non_hidden_files(f"threat_actors_added_data/{threat_actor}")
        threat_actor_splits = generate_threat_actor_splits(strings=txt_file_names, k=k, train=0.7, valid=0.2, test=0.1)
        all_splits[threat_actor] = threat_actor_splits
    return all_splits # dictionary mapping threat actor names to list of length k, 3, arbitrary


def process_file(threat_actor, file_name, reference_df, embeddings_matrix):
    """
    Processes a single file to extract MITRE technique frequencies.
    
    This function is designed to be run in parallel to improve performance when
    processing multiple files.
    
    Args:
        threat_actor (str): Name of the threat actor associated with the file
        file_name (str): Name of the file to process
        reference_df (DataFrame): DataFrame containing MITRE technique information
        embeddings_matrix (numpy.ndarray): Matrix of embeddings for all techniques
    
    Returns:
        tuple: (threat_actor, term_counts) where term_counts is a dictionary mapping 
               technique names to their counts
    """
    # This function will be executed in parallel
    term_counts = get_term_counts(txt_file=f"threat_actors_added_data/{threat_actor}/{file_name}", normalize=False, reference_df=reference_df, embeddings_matrix=embeddings_matrix)
    return threat_actor, term_counts

def process_split(splits, idx, reference_df, embeddings_matrix, threat_actor_probabilities):
    """
    Processes one k-fold split to build a Bayesian model for threat actor attribution.
    
    This function takes one of the k splits, processes all the training files in parallel,
    and calculates conditional probabilities P(MITRE code | threat actor) used for attribution.
    
    Args:
        splits (dict): Dictionary mapping threat actors to their k-fold splits
        idx (int): Index of the split to process (0 to k-1)
        reference_df (DataFrame): DataFrame containing MITRE technique information
        embeddings_matrix (numpy.ndarray): Matrix of embeddings for all techniques
        threat_actor_probabilities (dict): Prior probabilities for each threat actor
    
    Returns:
        tuple: (p_mitre_code_given_threat_actor, valid, test) where:
               - p_mitre_code_given_threat_actor is a nested dictionary mapping each threat actor to
                 a dictionary of P(MITRE code | threat actor) probabilities
               - valid is a dictionary mapping threat actors to validation files
               - test is a dictionary mapping threat actors to test files
    """
    # select just the split you need
    split = {threat_actor: threat_actor_splits[idx] for threat_actor, threat_actor_splits in splits.items()}

    # get train, valid, test -> maps each threat actor name to a list of file names
    train = {threat_actor: threat_actor_split[0] for threat_actor, threat_actor_split in split.items()}
    valid = {threat_actor: threat_actor_split[1] for threat_actor, threat_actor_split in split.items()}
    test = {threat_actor: threat_actor_split[2] for threat_actor, threat_actor_split in split.items()}

    # Dictionary to hold the combined results
    train_threat_actor_term_counts = {threat_actor: {} for threat_actor in train.keys()}

    # Using ThreadPoolExecutor to parallelize the file processing
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        # Prepare a list of tasks
        futures = []
        for threat_actor in train.keys():
            for file_name in train[threat_actor]:
                # Schedule the execution of each file processing
                future = executor.submit(process_file, threat_actor, file_name, reference_df, embeddings_matrix)
                futures.append(future)

        # As each future completes, collect the results
        for future in tqdm(concurrent.futures.as_completed(futures)):
            threat_actor, term_counts = future.result()
            # Here, you can combine term counts as required, for example:
            if threat_actor not in train_threat_actor_term_counts:
                train_threat_actor_term_counts[threat_actor] = term_counts
            else:
                # Assuming you want to sum the term counts from different files
                for term, count in term_counts.items():
                    if term in train_threat_actor_term_counts[threat_actor]:
                        train_threat_actor_term_counts[threat_actor][term] += count
                    else:
                        train_threat_actor_term_counts[threat_actor][term] = count

    total_mitre_code_counts = 0
    
    # for each threat actor, calculate probability of the mitre code given the threat actor, P(B | A)
    p_mitre_code_given_threat_actor = {}
    for threat_actor in train_threat_actor_term_counts.keys():
        normalize_val = sum(train_threat_actor_term_counts[threat_actor].values())
        total_mitre_code_counts += normalize_val
        p_mitre_code_given_threat_actor[threat_actor] = {key : val / normalize_val for key, val in train_threat_actor_term_counts[threat_actor].items()}

    return p_mitre_code_given_threat_actor, valid, test

def calculate_probabilities(actual_threat_actor, file, mitre_df, embeddings_matrix, p_mitre_code_given_threat_actor):
    """
    Calculates attribution scores for a test file and determines its rank.
    
    This function extracts MITRE techniques from a test file, then uses the
    conditional probabilities from the model to score different threat actors.
    It then determines the rank of the actual threat actor in the sorted list.
    
    Args:
        actual_threat_actor (str): The true threat actor for the file
        file (str): File name to process
        mitre_df (DataFrame): DataFrame containing MITRE technique information
        embeddings_matrix (numpy.ndarray): Matrix of embeddings for all techniques
        p_mitre_code_given_threat_actor (dict): Nested dictionary mapping threat actors to
                                               technique conditional probabilities
    
    Returns:
        dict: Dictionary with 'actual_ta' (the actual threat actor) and 
              'rank' (the position of the actual threat actor in the sorted list)
    """
    # Fetch term probabilities for each file
    test_term_probabilities = get_term_counts(
        txt_file=f"threat_actors_added_data/{actual_threat_actor}/{file}", 
        normalize=True, 
        reference_df=mitre_df, 
        embeddings_matrix=embeddings_matrix
    )
    threat_actor_scores = {}
    for threat_actor in p_mitre_code_given_threat_actor:
        score = 0
        for mitre_code in p_mitre_code_given_threat_actor[threat_actor]:
            if mitre_code in test_term_probabilities:
                score += p_mitre_code_given_threat_actor[threat_actor][mitre_code] * test_term_probabilities[mitre_code]
        threat_actor_scores[threat_actor] = score

    # Sort the dictionary by score in descending order and get the keys
    sorted_actors = sorted(threat_actor_scores, key=threat_actor_scores.get, reverse=True)

    # Find the rank of 'actual_threat_actor'
    rank = sorted_actors.index(actual_threat_actor) + 1

    return {"actual_ta" : actual_threat_actor, "rank": rank}

def validation(train_result, mitre_df, embeddings_matrix, test=False):
    """
    Evaluates the model on validation or test data.
    
    This function runs the attribution model on either validation or test files
    and calculates performance metrics, particularly the average rank of the 
    actual threat actor in the model's predictions.
    
    Args:
        train_result (tuple): Result from process_split (p_mitre_code_given_threat_actor, valid, test)
        mitre_df (DataFrame): DataFrame containing MITRE technique information
        embeddings_matrix (numpy.ndarray): Matrix of embeddings for all techniques
        test (bool, optional): Whether to evaluate on test data instead of validation. Defaults to False.
    
    Returns:
        DataFrame: DataFrame containing actual threat actors and their ranks
    """
    actual_threat_actor_test_probs = []
    
    # Run each of the items in validation sets -> calculate scores
    p_threat_actor_given_mitre_code, valid, test = train_result

    if test:
        split_to_use = test
    else:
        split_to_use = valid
    
    # List to hold probabilities
    ranks = []

    # Using ThreadPoolExecutor to parallelize the file processing
    num_workers = 15  # Adjust this based on your system capabilities and task requirements
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Prepare a list of futures
        futures = []
        for actual_threat_actor in split_to_use.keys():
            for file in valid[actual_threat_actor]:
                # Submit the processing function to the executor
                future = executor.submit(calculate_probabilities, actual_threat_actor, file, mitre_df, embeddings_matrix, p_threat_actor_given_mitre_code)
                futures.append(future)

        # As each future completes, gather the results
        for future in tqdm(concurrent.futures.as_completed(futures)):
            rank = future.result()
            ranks.append(rank)

    return pd.DataFrame(ranks)



if __name__ == "__main__":
    # data frame fo MITRE terms and their descriptions
    mitre_df = get_data()

    # embeddings of the descriptions of the MITRE terms in the same respective order
    embeddings_matrix = load_embeddings_matrix()
    #embeddings_matrix = create_embeddings(mitre_df)

    # # threat report -> MITRE codes -> scoring based off of hardcoded values
    # normalized_term_counts = get_term_counts(txt_file="Sandworm.txt", normalize=True, reference_df=mitre_df, embeddings_matrix=embeddings_matrix)
    # all_threat_actor_weights = get_hardcoded_threat_actor_weights(normalize=False) # un-normalize favors threat actors who are more studied / prolific
    # scores_df = calculate_scores(normalized_term_counts=normalized_term_counts, all_threat_actor_weights=all_threat_actor_weights)
    # with pd.option_context('display.max_rows', None):
    #     print(scores_df)
    #     print("___________________________")
    #     print()

    # # getting new weights logic
    # # list_non_hidden_files(path)

    # generate_splits for each threat_actor
    generated_splits = generate_splits()

    # calculate P(A) or threat_actor_probabilities
    threat_actor_probabilities = {}
    for threat_actor, threat_actor_splits in generated_splits.items():
        threat_actor_probabilities[threat_actor] = 1.0 / 29

    results = []
    train_results = []
    print("Going through data splits")
    for k in range(3): #k-fold
        train_result = process_split(generated_splits, k, mitre_df, embeddings_matrix, threat_actor_probabilities)
        train_results.append(train_result)

        validation_result = validation(train_result, mitre_df, embeddings_matrix, False)
        validation_result.to_csv(f"raw_validation_{k}.csv", index=False)
        cleaner = validation_result.groupby('actual_ta')['rank'].mean().reset_index()
        cleaner.to_csv(f"processed_validation_{k}.csv", index=False)

        results.append(validation_result['rank'].mean())
    
    print("Validation accuracy scores:")
    print("---------------------------")
    formatted_probs = map(str, results)
    print(", ".join(formatted_probs))

    results = np.array(results)
    print("RESULTS VECTOR!!!")
    print(results)

    print()
    print("Stats:")
    print("------")
    print(f"Mean : {np.mean(results)}")
    print(f"Standard Deviation: {np.std(results)}")
    
    # final steps
    top_idx = np.argmax(results)
    top_model = train_results[top_idx]
    p_threat_actor_given_mitre_code, valid, test = top_model

    # write out threat actor probs to a file
    transformed_weights = []
    for threat_actor in p_threat_actor_given_mitre_code.keys():
        new_weight = copy.deepcopy(p_threat_actor_given_mitre_code[threat_actor])
        new_weight["threat_actor"] = threat_actor
        transformed_weights.append(new_weight)
    
    df = pd.DataFrame(transformed_weights)
    desired_first_column = "threat_actor"
    ordered_columns = [desired_first_column] + [col for col in df.columns if col != desired_first_column]
    df = df[ordered_columns]

    df.to_csv('best_validation.csv', index=False)
    print()
    print("Wrote out threat actor probs to csv")
    print()

    # Crunch test split performance
    test_result = validation(train_result=top_model, mitre_df=mitre_df, embeddings_matrix=embeddings_matrix, test=True)
    print(f"Average test case probability: {test_result}")