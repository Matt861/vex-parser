import json
import csv
import os

# Load JSON file
vex_file_name = 'crt-maven-classpath-dependencies-vex.cdx.json'
vex_file_path = os.path.join('input', vex_file_name)
csv_file_name = f"{vex_file_name.split('-vex')[0]}-vulnerable-code.csv"
csv_file_path = os.path.join('output', csv_file_name)
vulnerable_code_dict = {}

with open(vex_file_path, 'r', encoding='utf-8') as file:
    data = json.load(file)

# Function to handle ".java" parsing for each item
def handle_class_and_method_parsing(item):
    if item.endswith(".java"):
        return item[:-5]  # Remove ".java"
    elif "." in item:
        last_dot_index = item.rfind(".")
        class_name = item[:last_dot_index]
        method_name = item[last_dot_index + 1:]
        if method_name.endswith("()"):
            method_name = method_name[:-2]  # Remove "()"
        return class_name, method_name
    else:
        return item

# Function to extract "Compromised code:"
def extract_compromised_code(detail):
    compromised_marker = "Compromised code:"
    patch_marker = "Patch commit"

    start_index = detail.find(compromised_marker)
    if start_index == -1:
        return None
        #return "Compromised code marker not found in detail"

    start_index += len(compromised_marker)

    end_index = detail.find(patch_marker, start_index)

    if end_index == -1:
        result = detail[start_index:].strip()
    else:
        result = detail[start_index:end_index].strip()

    # Split result by spaces into a list
    result_list = result.split()

    # Process each item in the list
    processed_items = [handle_class_and_method_parsing(item) for item in result_list]

    return processed_items

# Navigate through the JSON structure
try:
    vulnerabilities = data['vulnerabilities']

    for vulnerability in vulnerabilities:
        try:
            vuln_id = vulnerability['id']
            analysis = vulnerability['analysis']
            detail = analysis['detail']
            compromised_code_list = extract_compromised_code(detail)
            if not compromised_code_list is None:
                vulnerable_code_dict[vuln_id] = compromised_code_list
                for item in compromised_code_list:
                    if isinstance(item, tuple):
                        print(f"First part: {item[0]}\nSecond part: {item[1]}")
                    else:
                        print(item)
        except KeyError as e:
            print(f"Key not found in vulnerability: {e}")

except KeyError as e:
    print(f"Key not found in data: {e}")


def create_csv(vulnerabilities_dict, csv_file_path):
    with open(csv_file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Vulnerability Id", "Vulnerable Class", "Vulnerable Method"])

        for vuln_id, compromised_code_list in vulnerabilities_dict.items():
            for item in compromised_code_list:
                if isinstance(item, tuple):
                    vulnerable_class = item[0]
                    vulnerable_method = item[1]
                else:
                    vulnerable_class = item
                    vulnerable_method = ""
                writer.writerow([vuln_id, vulnerable_class, vulnerable_method])


# Create the CSV file
create_csv(vulnerable_code_dict, csv_file_path)

print(f"CSV file created at {csv_file_path}")



