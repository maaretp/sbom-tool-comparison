import subprocess
import json
import os

def get_sboms_for_images(image_name: str):
    command_syft_sbom = ["syft", "--output", "spdx-json", "--file", os.path.join("results", image_name, "sbom_syft.json"), image_name]
    subprocess.run(command_syft_sbom, capture_output=True, text=True, check=True)

    command_grype_sbom = ["grype", "--output", "json", "--file", os.path.join("results", image_name, "json_grype.json"), image_name]
    subprocess.run(command_grype_sbom, capture_output=True, text=True, check=True)

    command_docker_sbom = ["docker", "sbom", "--format", "spdx-json", "--output", os.path.join("results", image_name, "sbom_docker.json"), image_name]
    subprocess.run(command_docker_sbom, capture_output=True, text=True, check=True)

    command_scout_scout = ["docker", "scout", "sbom", "--format", "spdx", "--output", os.path.join("results", image_name, "sbom_scout.json"), image_name]
    subprocess.run(command_scout_scout, capture_output=True, text=True, check=True)

def get_component_info_grype_json(image: str, file_name: str, outfile_name: str):
    with open(os.path.join("results", image, file_name), 'r') as file:
        data = json.load(file)

    with open(os.path.join("results", image, "temp.txt"), 'w') as outfile:
        for match in data['matches']:
            package = match['artifact']
            outfile.write(f"{package['name']} {package['version']} {package['type']}\n")

    seen_lines = set()

    with open(os.path.join("results", image, "temp.txt"), 'r') as input_f, open(os.path.join("results", image, outfile_name), 'w') as output_f:
        for line in input_f:
            line = line.strip()
            if line not in seen_lines:
                output_f.write(line + '\n')
                seen_lines.add(line)

    with open(os.path.join("results", image, outfile_name), 'r') as file:
        lines = file.readlines()
        print(f"grype components identified: {len(lines)}")

def get_component_info_spdx_sbom(image: str, file_name: str, outfile_name: str):
    with open(os.path.join("results", image, file_name), 'r') as file:
        data = json.load(file)

    with open(os.path.join("results", image,"temp.txt"), 'w') as outfile:
        for package in data['packages']:
            outfile.write(f"{package['name']} {package['versionInfo']}\n")

    seen_lines = set()

    with open(os.path.join("results", image, "temp.txt"), 'r') as input_f, open(os.path.join("results", image, outfile_name), 'w') as output_f:
        for line in input_f:
            line = line.strip()
            if line not in seen_lines:
                output_f.write(line + '\n')
                seen_lines.add(line)

    with open(os.path.join("results", image, outfile_name), 'r') as file:
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

def create_summary(image):
    files = [os.path.join("results", image, 'components_docker.txt'),
             os.path.join("results", image, 'components_scout.txt'),
             os.path.join("results", image, 'components_syft.txt')]
    output_file = os.path.join("results", image, "summary.md")

    def parse_file(filename):
        return {package.strip(): True for package in open(filename)}

    parsed_files = [parse_file(filename) for filename in files]

    # Get unique package names
    all_packages = set()
    for packages in parsed_files:
        all_packages.update(packages.keys())
    all_packages = sorted(all_packages)

    table_header = "| {:<20} | {} |\n".format("Package", " | ".join(["{: <12}".format(f) for f in files]))

    separator = "|----------------------|" + "|".join(["------------" for _ in files]) + "|\n"

    table_rows = [table_header, separator]
    for package in all_packages:
        row = "| {:<20} |".format(package)
        for packages in parsed_files:
            if package in packages:
                row += " {: <10} |".format("Yes")
            else:
                row += " {: <10} |".format("No")
        table_rows.append(row + "\n")

    with open(output_file, 'w') as f:
        for row in table_rows:
            f.write(row)

    print("Summary written to", output_file)

def create_diffs(image):
    input_file_path = os.path.join("results", image, "summary.md")
    no_output_file_path = os.path.join("results", image,"summary_some_no.txt")
    yes_output_file_path = os.path.join("results", image, "summary_all_yes.txt")
    two_yes_output_file_path = os.path.join("results", image,"summary_two_yes.txt")
    two_no_output_file_path = os.path.join("results", image, "summary_two_no.txt")

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
image = "python:3.12-slim-bookworm"
images =["python:3.12-slim-bookworm",
         "node:18.16.1-alpine",
         "rabbitmq:3.12.12-management",
         "postgres:12.9-bullseye",
         "envoyproxy/envoy:v1.12.2",
         "python:3.10-buster",
         "electronuserland/builder:wine",
         "gradle:6.6.1-jdk11",
         "openjdk:11-jdk",
         "14-alpine",
         "18.20.2-alpine",
         "rabbitmq:3.13-management",
         "postgres:12.19-bookworm",
         "envoyproxy/envoy:v1.30.1",
         "python:3.13-slim-bookworm"]
get_sboms_for_images(image)
get_component_info_grype_json(image, "json_grype.json", "components_grype.txt")
syft = get_component_info_spdx_sbom(image, "sbom_syft.json", "components_syft.txt")
print (f"syft components identified: {syft}")
docker = get_component_info_spdx_sbom(image, "sbom_docker.json", "components_docker.txt")
print (f"docker components identified: {docker}")
scout = get_component_info_spdx_sbom(image, "sbom_scout.json", "components_scout.txt")
print (f"scout components identified: {scout}")
create_summary(image)
create_diffs(image)
print(f'Number of components found by all three: {do_counts(os.path.join("results", image,"summary_all_yes.txt"))}')
print(f'Number of components missed by two tools: {do_counts(os.path.join("results", image, "summary_two_no.txt"))}')
print(f'Number of components missed by some tool: {do_counts(os.path.join("results", image, "summary_some_no.txt"))}')
print(f'Number of components found two tools: {do_counts(os.path.join("results", image, "summary_two_yes.txt"))}')
