import subprocess
import json
import os

def modify_json(file_path, document_namespace, creator_org, creator_tool):
    with open(file_path, 'r') as file:
        data = json.load(file)

    data['documentNamespace'] = document_namespace
    data['creationInfo']['creators'] = [
        f"Organization: {creator_org}",
        f"Tool: {creator_tool}"
    ]

    with open(file_path, 'w') as file:
        json.dump(data, file, indent=2)


def get_sboms_for_images(image_name, document_namespace, creator_org, creator_tool):
    syft_json_path = os.path.join(base_folder, image_name, "sbom_syft.json")
    command_syft_sbom = ["syft", "--output", "spdx-json", "--file", os.path.join(base_folder, image_name, "sbom_syft.json"), image_name]
    subprocess.run(command_syft_sbom, capture_output=True, text=True, check=True)
    modify_json(syft_json_path, document_namespace, creator_org=creator_org, creator_tool=creator_tool)

    command_grype_sbom = ["grype", "--output", "json", "--file", os.path.join(base_folder, image_name, "json_grype.json"), image_name]
    subprocess.run(command_grype_sbom, capture_output=True, text=True, check=True)

    command_docker_sbom = ["docker", "sbom", "--format", "spdx-json", "--output", os.path.join(base_folder, image_name, "sbom_docker.json"), image_name]
    subprocess.run(command_docker_sbom, capture_output=True, text=True, check=True)

    command_scout_scout = ["docker", "scout", "sbom", "--format", "spdx", "--output", os.path.join(base_folder, image_name, "sbom_scout.json"), image_name]
    subprocess.run(command_scout_scout, capture_output=True, text=True, check=True)

def get_component_info_grype_json(image: str, file_name: str, outfile_name: str):
    with open(os.path.join(base_folder, image, file_name), 'r') as file:
        data = json.load(file)

    with open(os.path.join(base_folder, image, "temp.txt"), 'w') as outfile:
        for match in data['matches']:
            package = match['artifact']
            outfile.write(f"{package['name']} {package['version']} {package['type']}\n")

    seen_lines = set()

    with open(os.path.join(base_folder, image, "temp.txt"), 'r') as input_f, open(os.path.join(base_folder, image, outfile_name), 'w') as output_f:
        for line in input_f:
            line = line.strip()
            if line not in seen_lines:
                output_f.write(line + '\n')
                seen_lines.add(line)

    with open(os.path.join(base_folder, image, outfile_name), 'r') as file:
        lines = file.readlines()
        print(f"grype components identified: {len(lines)}")

def get_component_info_spdx_sbom(image: str, file_name: str, outfile_name: str):
    with open(os.path.join(base_folder, image, file_name), 'r') as file:
        data = json.load(file)

    with open(os.path.join(base_folder, image,"temp.txt"), 'w') as outfile:
        for package in data['packages']:
            outfile.write(f"{package['name']} {package['versionInfo']}\n")

    seen_lines = set()

    with open(os.path.join(base_folder, image, "temp.txt"), 'r') as input_f, open(os.path.join(base_folder, image, outfile_name), 'w') as output_f:
        for line in input_f:
            line = line.strip()
            if line not in seen_lines:
                output_f.write(line + '\n')
                seen_lines.add(line)

    with open(os.path.join(base_folder, image, outfile_name), 'r') as file:
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
    files = [os.path.join(base_folder, image, 'components_docker.txt'),
             os.path.join(base_folder, image, 'components_scout.txt'),
             os.path.join(base_folder, image, 'components_syft.txt')]
    output_file = os.path.join(base_folder, image, "summary.md")

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
    input_file_path = os.path.join(base_folder, image, "summary.md")
    no_output_file_path = os.path.join(base_folder, image,"summary_some_no.txt")
    yes_output_file_path = os.path.join(base_folder, image, "summary_all_yes.txt")
    two_yes_output_file_path = os.path.join(base_folder, image,"summary_two_yes.txt")
    two_no_output_file_path = os.path.join(base_folder, image, "summary_two_no.txt")

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
base_folder = "results"
images = {
    # "python:3.12-slim-bookworm": ("https://hub.docker.com/layers/library/python/3.12-slim-bookworm/images/sha256-f0c6bc1ab7b1ab270bbb612a31a67a7938d6171183ddce9121f04984ab3df44e", "Docker, Inc", "docker-scout-1.6.3"),
    # "node:18.16.1-alpine": ("https://hub.docker.com/layers/library/node/18.16.1-alpine/images/sha256-bf6c61feabc1a1bd565065016abe77fa378500ec75efa67f5b04e5e5c4d447cd", "Node.js Foundation", "node-scout-1.0.0"),
    # "rabbitmq:3.12.12-management": ("https://hub.docker.com/layers/library/rabbitmq/3.12.12-management-alpine/images/sha256-52a7d8b44193ddd20d7f4ae5ff1bd75c9b0ea548e551aca200cf2512ba785dcc", "RabbitMQ Team", "rabbitmq-scout-1.2"),
    # "envoyproxy/envoy:v1.12.2": ("https://hub.docker.com/layers/envoyproxy/envoy/v1.12.2/images/sha256-b36ee021fc4d285de7861dbaee01e7437ce1d63814ead6ae3e4dfcad4a951b2e", "Envoy Proxy", "envoy-scout-1.12"),
    # "python:3.10-buster": ("https://hub.docker.com/layers/library/python/3.10.4-buster/images/sha256-4e6014145bbee13b7635b6075071fc6fd9faadfe6374a7f1f3c9d169f99165e5", "Docker, Inc", "docker-scout-1.6.3"),
    # "electronuserland/builder:wine": ("https://hub.docker.com/layers/electronuserland/builder/wine-05.18/images/sha256-a23a01d87e743ec4f22d4b4bf84ab7b0b1f2698a0aa5e2efa7e38407b5983ed3", "Electron Userland", "electron-scout-2.0"),
    # "openjdk:11-jdk": ("https://hub.docker.com/_/openjdk", "OpenJDK Team", "jdk-scout-11.0"),
    # "rabbitmq:3.13-management": ("https://hub.docker.com/layers/library/rabbitmq/3.13-management/images/sha256-4d9117df59366b8bb042fc10e7d0e38af7fcb43354cddfb7e20da9c928b00172", "RabbitMQ Team", "rabbitmq-scout-1.3"),
    # "envoyproxy/envoy:v1.30.1": ("https://hub.docker.com/layers/envoyproxy/envoy-contrib/v1.30.1/images/sha256-0554e0da764b5a107563bf84ca781a4545e8d162a1347e56cd9ffdecc6bdba99?context=explore", "Envoy Proxy", "envoy-scout-1.30"),
    # "almalinux:8.9-minimal": ("https://hub.docker.com/layers/library/almalinux/8.9-minimal/images/sha256-afae980355243ea2e42fdf798eb9085560796d93bfc421463b194b021b3d8bad", "AlmaLinux", "almalinux-scout-8.9"),
    # "node:20.12.2-alpine3.19": ("https://hub.docker.com/layers/library/node/20.12.2-alpine3.19/images/sha256-6804d8d259b84b62c908fde68122a1e08c8478bcf979c33d6e71dee09968aeae", "Node.js Foundation", "node-scout-20.12"),
    # "nginx:alpine3.19-slim": ("https://hub.docker.com/layers/library/nginx/alpine3.19-slim/images/sha256-99453d9d4b0df77ce6e1ec81e2b4712a48d9cd5073a4541b3afaaf5d8896a566", "NGINX, Inc", "nginx-scout-1.19"),
    # "eclipse-temurin:17.0.10_7-jre-alpine": ("https://hub.docker.com/layers/library/eclipse-temurin/17.0.10_7-jre-alpine/images/sha256-597871ad55f87f44e9e635c998538706776241e3295f24b8b4bbd121326e887a", "Eclipse Foundation", "temurin-scout-17.0"),
    "postgres:12.9-bullseye": ("https://hub.docker.com/layers/library/postgres/12.9/images/sha256-2ee9cddccf6dd8dd6dc3ad0e25d955626db48ae0b60983d10767c24289371985", "PostgreSQL", "postgres-scout-12.9"),
    "postgres:12.19-bookworm": ("https://hub.docker.com/layers/library/postgres/12.19-bookworm/images/sha256-a29d7b1c139777a1acb2d96ad5517768b3830c4c7a2c3d56c75990252406539e?context=explore", "PostgreSQL", "postgres-scout-12.19"),
    "kartoza/geoserver:2.11.2": ("https://github.com/osgeo4inspire/geoserver-bsg", "Kartoza", "geoserver-scout-2.11"),
    "gradle:6.6.1-jdk11": ("https://hub.docker.com/layers/library/gradle/6.3.0-jdk11/images/sha256-89b08ee2627fb1d1c4fa22bd32d19993158a5c7adc4588918d4d75f5da894d4f", "Gradle Inc", "gradle-scout-6.6"),
    "rockylinux/rockylinux": ("https://hub.docker.com/r/rockylinux/rockylinux", "Rocky Linux", "rockylinux-scout-1.0"),
    "alpine/helm": ("https://hub.docker.com/r/alpine/helm", "Alpine Linux", "helm-scout-3.0"),
    "14-alpine": ("https://hub.docker.com/layers/library/node/14-alpine/images/sha256-b5fd5877b6bb2bb443c63ea0e7a8dc5197d8f01ed4a8ca1416a203c52bcf283c", "Node.js Foundation", "node-scout-14.0"),
    "18.20.2-alpine":("https://hub.docker.com/layers/andrius/asterisk/alpine-18.20.2/images/sha256-c03e8a5ed1443f7096bec28be7fca509f80aee75324df51481d766c1b0446cf2","Node.js Foundation", "node-scout-18.20"),
    "python:3.13-slim-bookworm": ("https://hub.docker.com/layers/library/python/3.13-rc-slim-bookworm/images/sha256-c72f282dcba740c9ba64b5334a9887adafbbea530f12be4ead3a789db898ddac?context=explore", "Docker, Inc", "docker-scout-1.6.3")
}


""" images =["python:3.12-slim-bookworm",
         "node:18.16.1-alpine",
         "rabbitmq:3.12.12-management",
         "envoyproxy/envoy:v1.12.2",
         "python:3.10-buster",
         "electronuserland/builder:wine",
         "openjdk:11-jdk",
         "rabbitmq:3.13-management",
         "envoyproxy/envoy:v1.30.1",
         "almalinux:8.9-minimal",
         "node", #"20.12.2-alpine3.19",
         "nginx", #"alpine3.19-slim",
         "eclipse-temurin", #"17.0.10_7-jre-alpine"
         #"postgres:12.9-bullseye",  #fails to get versioninfo, syft
         #"postgres:12.19-bookworm", #fails to get versioninfo, syft
         #"kartoza/geoserver:2.11.2", #fails to get versioninfo, syft
         #"gradle:6.6.1-jdk11", #fails to get versioninfo, syft
         #"rockylinux/rockylinux", #fails to get versioninfo, syft
         #"alpine/helm", #fails to get versioninfo, syft
         #"14-alpine", #non-zero exit status
         #"18.20.2-alpine", #non-zero exit status
         #"python:3.13-slim-bookworm", #non-zero exit status
         ] """

#for image, (namespace, org, tool) in images.items():
for image, (document_namespace, creator_org, creator_tool) in images.items():
    print(f"\nProcessing image: {image}")
    results_location = os.path.join(base_folder, image)
    #get_sboms_for_images(image)
    get_sboms_for_images(image, document_namespace, creator_org, creator_tool)
    get_component_info_grype_json(image, "json_grype.json", "components_grype.txt")
    syft = get_component_info_spdx_sbom(image, "sbom_syft.json", "components_syft.txt")
    print (f"syft components identified: {syft}")
    docker = get_component_info_spdx_sbom(image, "sbom_docker.json", "components_docker.txt")
    print (f"docker components identified: {docker}")
    scout = get_component_info_spdx_sbom(image, "sbom_scout.json", "components_scout.txt")
    print (f"scout components identified: {scout}")
    create_summary(image)
    create_diffs(image)
    print(f'Number of components found by all three: {do_counts(os.path.join(results_location,"summary_all_yes.txt"))}')
    print(f'Number of components missed by two tools: {do_counts(os.path.join(results_location, "summary_two_no.txt"))}')
    print(f'Number of components missed by some tool: {do_counts(os.path.join(results_location, "summary_some_no.txt"))}')
    print(f'Number of components found two tools: {do_counts(os.path.join(results_location, "summary_two_yes.txt"))}')
