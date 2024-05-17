import subprocess
import json

def get_sboms_for_images(image_name: str):
    command_syft_sbom = ["syft", "--output", "spdx-json", "--file", "sbom_syft.json", image_name]
    subprocess.run(command_syft_sbom, capture_output=True, text=True, check=True)

    command_grype_sbom = ["grype", "--output", "json", "--file", "json_grype.json", image_name]
    subprocess.run(command_grype_sbom, capture_output=True, text=True, check=True)

    command_docker_sbom = ["docker", "sbom", "--format", "spdx-json", "--output", "sbom_docker.json", image_name]
    subprocess.run(command_docker_sbom, capture_output=True, text=True, check=True)

    command_scout_scout = ["docker", "scout", "sbom", "--format", "spdx", "--output", "sbom_scout.json", image_name]
    subprocess.run(command_scout_scout, capture_output=True, text=True, check=True)

def get_component_info_grype_json(file_name: str, outfile_name: str):
    with open(file_name, 'r') as file:
        data = json.load(file)

    with open("temp.txt", 'w') as outfile:
        for match in data['matches']:
            package = match['artifact']
            outfile.write(f"{package['name']} {package['version']} {package['type']}\n")

    seen_lines = set()

    with open("temp.txt", 'r') as input_f, open(outfile_name, 'w') as output_f:
        for line in input_f:
            line = line.strip()
            if line not in seen_lines:
                output_f.write(line + '\n')
                seen_lines.add(line)

    with open(outfile_name, 'r') as file:
        lines = file.readlines()
        print(f"grype components identified: {len(lines)}")

def get_component_info_spdx_sbom(file_name: str, outfile_name: str):
    with open(file_name, 'r') as file:
        data = json.load(file)

    with open("temp.txt", 'w') as outfile:
        for package in data['packages']:
            outfile.write(f"{package['name']} {package['versionInfo']}\n")

    seen_lines = set()

    with open("temp.txt", 'r') as input_f, open(outfile_name, 'w') as output_f:
        for line in input_f:
            line = line.strip()
            if line not in seen_lines:
                output_f.write(line + '\n')
                seen_lines.add(line)

    with open(outfile_name, 'r') as file:
        lines = file.readlines()
        return len(lines)

def parse_file(filename):
    packages = {}
    with open(filename, 'r') as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) >= 2:
                package_name = parts[0]
                packages[package_name] = ' '.join(parts[1:])
    return packages

def create_summary():
    files = ['components_docker.txt', 'components_scout.txt', 'components_syft.txt']
    output_file = "summary.md"

    def parse_file(filename):
        # Assuming parse_file returns a dictionary with package names as keys.
        # This is a placeholder implementation.
        return {package.strip(): True for package in open(filename)}

    # Parse each file
    parsed_files = [parse_file(filename) for filename in files]

    # Get unique package names
    all_packages = set()
    for packages in parsed_files:
        all_packages.update(packages.keys())
    all_packages = sorted(all_packages)

    # Create table header
    table_header = "| {:<20} | {} |\n".format("Package", " | ".join(["{: <12}".format(f) for f in files]))

    # Create separator
    separator = "|----------------------|" + "|".join(["------------" for _ in files]) + "|\n"

    # Create table rows
    table_rows = [table_header, separator]
    for package in all_packages:
        row = "| {:<20} |".format(package)
        for packages in parsed_files:
            if package in packages:
                row += " {: <10} |".format("Yes")
            else:
                row += " {: <10} |".format("No")
        table_rows.append(row + "\n")

    # Write the table to the output file
    with open(output_file, 'w') as f:
        for row in table_rows:
            f.write(row)

    print("Summary written to", output_file)


def create_summary_old():
    files = ['components_docker.txt', 'components_scout.txt', 'components_syft.txt']
    output_file = "summary.md"

    # Parse each file
    parsed_files = [parse_file(filename) for filename in files]

    # Get unique package names
    all_packages = set()
    for packages in parsed_files:
        all_packages.update(packages.keys())
    all_packages = sorted(all_packages)

    # Create table header
    table_header = "| {:<20} | {} |\n".format("", " | ".join(["{: <10}".format(f) for f in files]))

    # Create separator
    separator = "| {} |\n".format('-' * len(table_header.split('|')[1]))

    # Create table rows
    table_rows = [table_header, separator]
    for package in all_packages:
        row = "| {:<20} |".format(package)
        for packages in parsed_files:
            if package in packages:
                row += " Yes |"
            else:
                row += " No     |"
        table_rows.append(row + "\n")

    # Write the table to the output file
    with open(output_file, 'w') as f:
        for row in table_rows:
            f.write(row)

    print("Summary written to", output_file)

def create_diffs():
    input_file_path = "summary.md"
    no_output_file_path = "summary_some_no.txt"
    yes_output_file_path = "summary_all_yes.txt"
    two_yes_output_file_path = "summary_two_yes.txt"
    two_no_output_file_path = "summary_two_no.txt"

    with open(input_file_path, "r") as input_file, open(no_output_file_path, "w") as output_file:
        for line in input_file:
            if "No" in line:
                output_file.write(line)

    with open(input_file_path, "r") as input_file, open(yes_output_file_path, "w") as output_file:
        for line in input_file:
            if line.count("Yes") == 3:
                output_file.write(line)

    with open(input_file_path, "r") as input_file, open(two_yes_output_file_path, "w") as output_file:
        for line in input_file:
            if line.count("Yes") == 2:
                output_file.write(line)

    with open(input_file_path, "r") as input_file, open(two_no_output_file_path, "w") as output_file:
        for line in input_file:
            if line.count("No") == 2:
                output_file.write(line)

def do_counts(input_file):
    with open(input_file, "r") as file:
        count = 0
        for line in file:
            count += 1
        return count

#samples with one docker image for now
get_sboms_for_images("python:3.12-slim-bookworm")
get_component_info_grype_json("json_grype.json", "components_grype.txt")
syft = get_component_info_spdx_sbom("sbom_syft.json", "components_syft.txt")
print (f"syft components identified: {syft}")
docker = get_component_info_spdx_sbom("sbom_docker.json", "components_docker.txt")
print (f"docker components identified: {docker}")
scout = get_component_info_spdx_sbom("sbom_scout.json", "components_scout.txt")
print (f"scout components identified: {scout}")
create_summary()
create_diffs()
print(f"Number of components found by all three: {do_counts('summary_all_yes.txt')}")
print(f"Number of components missed by two tools: {do_counts('summary_two_no.txt')}")
print(f"Number of components missed by some tool: {do_counts('summary_some_no.txt')}")
print(f"Number of components found two tools: {do_counts('summary_two_yes.txt')}")
