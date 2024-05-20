#get lists from three sources with components, versions and licenses, and sources that identified the component
#combine the three sources while removing duplicates to create a full listing
# Work through the two main base images of 1st pilot

import subprocess
import json
import os

json_folder = "jsons"

def get_sbom_for_image(image_name: str):
    #create  folder for json_folder if it does not exist
    if not os.path.exists(json_folder):
        os.makedirs(json_folder)

    command_scout_scout = ["docker", "scout", "sbom", "--format", "spdx", "--output", os.path.join(json_folder, image_name[1]+"_scout.json"), image_name[0]]
    subprocess.run(command_scout_scout, capture_output=True, text=True, check=True)

    command_syft_sbom = ["syft", "--output", "spdx-json", "--file", os.path.join(json_folder, image_name[1]+"_syft.json"), image_name[0]]
    subprocess.run(command_syft_sbom, capture_output=True, text=True, check=True)

    command_docker_sbom = ["docker", "sbom", "--format", "spdx-json", "--output", os.path.join(json_folder, image_name[1]+"_docker.json"), image_name[0]]
    subprocess.run(command_docker_sbom, capture_output=True, text=True, check=True)

def get_sboms_for_images():
    images =[("python:3.12-slim-bookworm", "bookworm"),
             ("node:18.16.1-alpine", "alpine")]

    for image in images:
        get_sbom_for_image(image)

def create_component_listing(folder_name: str):
    all_components = set()
    for file in os.listdir(folder_name):
        with open(os.path.join(folder_name, file), 'r') as json_file:
            data = json.load(json_file)
            for package in data['packages']:
                try:
                    all_components.add(f"{package['name']} {package['versionInfo']}\n")
                except KeyError:
                    all_components.add(f"{package['name']} MISSING\n")

    #sort set in alphabetical order
    all_components = sorted(all_components)

    with open("all_components.txt", 'w') as outfile:
        for line in all_components:
            outfile.write(line)

def create_license_listing(folder_name: str):

    all_licenses = set()

    with open("all_components.txt", 'r') as file:
        for line in file:
            component = line.strip()
            for file in os.listdir(folder_name):
                with open(os.path.join(folder_name, file), 'r') as json_file:
                    data = json.load(json_file)
                    for package in data['packages']:
                        if package['name'] == component.split()[0]:
                            try:
                                if package['licenseDeclared'] == "NOASSERTION" and package['licenseConcluded'] == "NOASSERTION":
                                    all_licenses.add(f"{package['name']} {package['versionInfo']}   MISSING from {file}\n")
                                elif package['licenseDeclared'] == "NOASSERTION":
                                    all_licenses.add(f"{package['name']}    {package['versionInfo']}    {package['licenseConcluded']}\n")
                                elif package['licenseConcluded'] == "NOASSERTION":
                                    all_licenses.add(f"{package['name']}    {package['versionInfo']}    {package['licenseDeclared']}\n")
                                elif package['licenseDeclared'] == package['licenseConcluded']:
                                    all_licenses.add(f"{package['name']}    {package['versionInfo']}    {package['licenseDeclared']}\n")
                                else:
                                    all_licenses.add(f"{package['name']}    {package['versionInfo']}    {package['licenseDeclared']}    {package['licenseConcluded']}\n")
                            except KeyError:
                                all_licenses.add(f"{package['name']}\n")

    all_licenses = sorted(all_licenses)

    with open("all_licenses.txt", 'w') as outfile:
        for line in all_licenses:
            outfile.write(line)

def print_statistics():
    with open("all_components.txt", 'r') as file:
        lines = file.readlines()
        print(f"Unique component-version -pairs identified: {len(lines)}")

    for file in os.listdir(json_folder):
        with open(os.path.join(json_folder, file), 'r') as json_file:
            data = json.load(json_file)
            print(f"{file}: {len(data['packages'])}")

    with open("all_licenses.txt", 'r') as file:
        lines = file.readlines()
        print(f"Full component - license listing: {len(lines)}")


def main():
    get_sboms_for_images()
    create_component_listing(json_folder)
    create_license_listing(json_folder)
    print_statistics()


if __name__ == "__main__":
    main()