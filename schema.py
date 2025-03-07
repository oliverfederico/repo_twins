#!/usr/bin/env python3
import argparse
import os
import json
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
import re
from pathlib import Path


def strip_namespace(tag):
    """Extract the class name without namespace"""
    if '}' in tag:
        return tag.split('}')[-1]
    return tag


def analyze_xml_structure(xml_file):
    """
    Analyze the structure of an XML file.

    Args:
        xml_file (str): Path to the XML file

    Returns:
        dict: Structure information about the XML file
    """
    results = {
        "file": os.path.basename(xml_file),
        "full_path": os.path.abspath(xml_file),
        "size_bytes": os.path.getsize(xml_file),
        "elements": defaultdict(lambda: {
            "count": 0,
            "attributes": defaultdict(list),  # Changed from set to list
            "child_elements": Counter(),
            "parent_elements": Counter(),
            "sample_content": [],
            "has_text_content": False
        })
    }

    try:
        # Use iterparse to handle large files
        parent_stack = []
        context = ET.iterparse(xml_file, events=('start', 'end'))

        for event, elem in context:
            tag = strip_namespace(elem.tag)

            if event == 'start':
                # Process element start
                results["elements"][tag]["count"] += 1

                # Record parent-child relationships
                if parent_stack:
                    parent_tag = parent_stack[-1]
                    results["elements"][parent_tag]["child_elements"][tag] += 1
                    results["elements"][tag]["parent_elements"][parent_tag] += 1

                # Record attributes
                for attr_name, attr_value in elem.attrib.items():
                    type_name = str(type(attr_value).__name__)
                    if type_name not in results["elements"][tag]["attributes"][attr_name]:
                        results["elements"][tag]["attributes"][attr_name].append(type_name)

                    # Add a sample of attribute values (up to 3)
                    sample_key = f"sample_{attr_name}_values"
                    if sample_key not in results["elements"][tag]:
                        results["elements"][tag][sample_key] = []

                    if len(results["elements"][tag][sample_key]) < 3 and attr_value:
                        # Truncate very long values
                        sample_value = attr_value[:100] + "..." if len(attr_value) > 100 else attr_value
                        results["elements"][tag][sample_key].append(sample_value)

                # Check for text content
                if elem.text and elem.text.strip():
                    results["elements"][tag]["has_text_content"] = True

                    # Store sample content (up to 3)
                    if len(results["elements"][tag]["sample_content"]) < 3:
                        # Truncate very long content
                        content = elem.text.strip()
                        sample_content = content[:100] + "..." if len(content) > 100 else content
                        results["elements"][tag]["sample_content"].append(sample_content)

                # Add to parent stack
                parent_stack.append(tag)

            elif event == 'end':
                # Remove from parent stack when element ends
                if parent_stack and parent_stack[-1] == tag:
                    parent_stack.pop()

                # Clear element to free memory
                elem.clear()

        # Convert defaultdicts and counters to regular dicts for JSON serialization
        for tag in results["elements"]:
            results["elements"][tag]["attributes"] = dict(results["elements"][tag]["attributes"])
            results["elements"][tag]["child_elements"] = dict(results["elements"][tag]["child_elements"])
            results["elements"][tag]["parent_elements"] = dict(results["elements"][tag]["parent_elements"])

        results["elements"] = dict(results["elements"])
        return results

    except Exception as e:
        return {
            "file": os.path.basename(xml_file),
            "error": str(e),
            "elements": {}
        }


def analyze_json_structure(json_file):
    """
    Analyze the structure of a JSON file.

    Args:
        json_file (str): Path to the JSON file

    Returns:
        dict: Structure information about the JSON file
    """
    results = {
        "file": os.path.basename(json_file),
        "full_path": os.path.abspath(json_file),
        "size_bytes": os.path.getsize(json_file),
        "structure": {}
    }

    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Analyze structure based on first few items if list
        if isinstance(data, list):
            results["type"] = "array"
            results["count"] = len(data)

            if data:
                # Analyze first 5 items at most
                sample_count = min(5, len(data))
                samples = data[:sample_count]

                # Find common keys and types
                field_analysis = defaultdict(lambda: {"types": Counter(), "sample_values": []})

                for i, item in enumerate(samples):
                    if isinstance(item, dict):
                        for key, value in item.items():
                            field_analysis[key]["types"][type(value).__name__] += 1

                            # Add sample value if we have fewer than 3
                            if len(field_analysis[key]["sample_values"]) < 3:
                                sample_value = str(value)
                                if len(sample_value) > 100:
                                    sample_value = sample_value[:100] + "..."
                                field_analysis[key]["sample_values"].append(sample_value)

                # Convert to regular dict
                results["field_analysis"] = {
                    key: {
                        "types": dict(value["types"]),
                        "sample_values": value["sample_values"]
                    }
                    for key, value in field_analysis.items()
                }

        elif isinstance(data, dict):
            results["type"] = "object"
            results["structure"] = analyze_dict_structure(data)
        else:
            results["type"] = type(data).__name__
            results["value"] = str(data) if len(str(data)) < 100 else str(data)[:100] + "..."

        return results

    except Exception as e:
        return {
            "file": os.path.basename(json_file),
            "error": str(e)
        }


def analyze_dict_structure(data, max_depth=3, current_depth=0):
    """
    Recursively analyze dictionary structure.

    Args:
        data (dict): Dictionary to analyze
        max_depth (int): Maximum recursion depth
        current_depth (int): Current recursion depth

    Returns:
        dict: Structure information
    """
    if current_depth >= max_depth:
        return {"max_depth_reached": True}

    result = {}

    for key, value in data.items():
        if isinstance(value, dict):
            if current_depth < max_depth - 1:
                result[key] = {
                    "type": "object",
                    "structure": analyze_dict_structure(value, max_depth, current_depth + 1)
                }
            else:
                result[key] = {"type": "object", "max_depth_reached": True}

        elif isinstance(value, list):
            result[key] = {"type": "array", "count": len(value)}

            if value and current_depth < max_depth - 1:
                # Analyze first item as sample
                sample = value[0]
                if isinstance(sample, dict):
                    result[key]["sample_structure"] = analyze_dict_structure(sample, max_depth, current_depth + 1)
                else:
                    result[key]["sample_type"] = type(sample).__name__
                    if len(value) > 1:
                        # Check if all items are the same type
                        types = {type(item).__name__ for item in value[:5]}  # Check first 5 items
                        result[key]["element_types"] = list(types)  # Convert set to list
        else:
            result[key] = {
                "type": type(value).__name__,
            }

            # Add sample value
            if value is not None:
                sample_value = str(value)
                if len(sample_value) > 100:
                    sample_value = sample_value[:100] + "..."
                result[key]["sample_value"] = sample_value

    return result


def get_input_files(input_dir, file_extensions=None):
    """
    Get all files with specified extensions from input directory.

    Args:
        input_dir (str): Path to input directory
        file_extensions (list): List of file extensions to include

    Returns:
        list: List of file paths
    """
    if file_extensions is None:
        file_extensions = ['.xml', '.json']

    files = []

    for root, _, filenames in os.walk(input_dir):
        for filename in filenames:
            if any(filename.lower().endswith(ext) for ext in file_extensions):
                files.append(os.path.join(root, filename))

    return files


def generate_summary(results):
    """
    Generate a summary of the analyzed files.

    Args:
        results (dict): Analysis results

    Returns:
        dict: Summary information
    """
    summary = {
        "total_files_analyzed": len(results),
        "file_types": defaultdict(int),
        "xml_elements": defaultdict(int),
        "common_attributes": defaultdict(int),
        "error_files": []
    }

    # Process XML file results
    xml_files = [r for r in results if os.path.splitext(r["file"])[1].lower() == '.xml']
    json_files = [r for r in results if os.path.splitext(r["file"])[1].lower() == '.json']

    summary["file_types"][".xml"] = len(xml_files)
    summary["file_types"][".json"] = len(json_files)

    # Count elements across all XML files
    for result in xml_files:
        if "error" in result:
            summary["error_files"].append(result["file"])
            continue

        for elem_name, elem_data in result.get("elements", {}).items():
            summary["xml_elements"][elem_name] += elem_data.get("count", 0)

            # Track common attributes
            for attr_name in elem_data.get("attributes", {}):
                summary["common_attributes"][attr_name] += 1

    # Sort elements and attributes by frequency
    summary["xml_elements"] = dict(sorted(
        summary["xml_elements"].items(),
        key=lambda x: x[1],
        reverse=True
    ))

    summary["common_attributes"] = dict(sorted(
        summary["common_attributes"].items(),
        key=lambda x: x[1],
        reverse=True
    ))

    return dict(summary)  # Convert defaultdict to regular dict


def convert_sets_to_lists(obj):
    """
    Recursively convert sets to lists for JSON serialization.

    Args:
        obj: Any Python object

    Returns:
        Object with all sets converted to lists
    """
    if isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {key: convert_sets_to_lists(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_sets_to_lists(item) for item in obj]
    elif hasattr(obj, "items"):  # Handle defaultdict and Counter
        return {key: convert_sets_to_lists(value) for key, value in obj.items()}
    else:
        return obj


def save_results(results, summary, output_dir):
    """
    Save analysis results to output directory.

    Args:
        results (list): Analysis results
        summary (dict): Summary information
        output_dir (str): Path to output directory
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Convert any sets to lists for JSON serialization
    serializable_results = convert_sets_to_lists(results)
    serializable_summary = convert_sets_to_lists(summary)

    # Save detailed results
    with open(os.path.join(output_dir, "schema_analysis_details.json"), 'w', encoding='utf-8') as f:
        json.dump(serializable_results, f, indent=2)

    # Save summary
    with open(os.path.join(output_dir, "schema_analysis_summary.json"), 'w', encoding='utf-8') as f:
        json.dump(serializable_summary, f, indent=2)

    # Generate a human-readable report
    with open(os.path.join(output_dir, "schema_report.txt"), 'w', encoding='utf-8') as f:
        f.write("# SCHEMA ANALYSIS REPORT\n\n")

        f.write(f"Total files analyzed: {summary['total_files_analyzed']}\n")

        f.write("\n## FILE TYPES\n")
        for ext, count in summary['file_types'].items():
            f.write(f"{ext}: {count} files\n")

        if summary["error_files"]:
            f.write("\n## FILES WITH ERRORS\n")
            for error_file in summary["error_files"]:
                f.write(f"- {error_file}\n")

        f.write("\n## TOP XML ELEMENTS (by frequency)\n")
        for elem, count in list(summary["xml_elements"].items())[:20]:  # Top 20
            f.write(f"{elem}: {count} occurrences\n")

        f.write("\n## TOP COMMON ATTRIBUTES\n")
        for attr, count in list(summary["common_attributes"].items())[:20]:  # Top 20
            f.write(f"{attr}: used in {count} element types\n")

        # Add detailed XML element information
        f.write("\n## DETAILED XML ELEMENT INFORMATION\n")

        # Get all XML files that didn't have errors
        xml_files = [r for r in results
                     if os.path.splitext(r["file"])[1].lower() == '.xml'
                     and "error" not in r]

        # Create a combined view of elements across files
        combined_elements = {}

        for result in xml_files:
            for elem_name, elem_data in result.get("elements", {}).items():
                if elem_name not in combined_elements:
                    combined_elements[elem_name] = {
                        "total_count": 0,
                        "attributes": defaultdict(list),
                        "child_elements": Counter(),
                        "parent_elements": Counter(),
                        "sample_content": [],
                        "files": []
                    }

                combined_elements[elem_name]["total_count"] += elem_data.get("count", 0)
                if result["file"] not in combined_elements[elem_name]["files"]:
                    combined_elements[elem_name]["files"].append(result["file"])

                # Combine attributes
                for attr_name, attr_types in elem_data.get("attributes", {}).items():
                    if isinstance(attr_types, list):
                        for attr_type in attr_types:
                            if attr_type not in combined_elements[elem_name]["attributes"][attr_name]:
                                combined_elements[elem_name]["attributes"][attr_name].append(attr_type)
                    else:
                        if attr_types not in combined_elements[elem_name]["attributes"][attr_name]:
                            combined_elements[elem_name]["attributes"][attr_name].append(attr_types)

                # Combine child elements
                for child, count in elem_data.get("child_elements", {}).items():
                    combined_elements[elem_name]["child_elements"][child] += count

                # Combine parent elements
                for parent, count in elem_data.get("parent_elements", {}).items():
                    combined_elements[elem_name]["parent_elements"][parent] += count

                # Combine sample content
                if elem_data.get("sample_content"):
                    for sample in elem_data["sample_content"][:2]:  # Limit to 2 samples per file
                        if sample not in combined_elements[elem_name]["sample_content"]:
                            combined_elements[elem_name]["sample_content"].append(sample)

        # Sort elements by total count
        sorted_elements = sorted(
            combined_elements.items(),
            key=lambda x: x[1]["total_count"],
            reverse=True
        )

        # Write detailed information for each element
        for elem_name, elem_data in sorted_elements:
            f.write(f"\n### {elem_name}\n")
            f.write(f"Total occurrences: {elem_data['total_count']}\n")
            f.write(f"Found in {len(elem_data['files'])} files\n")

            # Attributes
            if elem_data["attributes"]:
                f.write("\nAttributes:\n")
                for attr_name, attr_types in elem_data["attributes"].items():
                    f.write(f"- {attr_name} (types: {', '.join(attr_types)})\n")

            # Child elements
            if elem_data["child_elements"]:
                f.write("\nMost common child elements:\n")
                for child, count in sorted(elem_data["child_elements"].items(), key=lambda x: x[1], reverse=True)[:5]:
                    f.write(f"- {child}: {count} occurrences\n")

            # Parent elements
            if elem_data["parent_elements"]:
                f.write("\nMost common parent elements:\n")
                for parent, count in sorted(elem_data["parent_elements"].items(), key=lambda x: x[1], reverse=True)[:5]:
                    f.write(f"- {parent}: {count} occurrences\n")

            # Sample content
            if elem_data["sample_content"]:
                f.write("\nSample content:\n")
                for sample in elem_data["sample_content"][:5]:  # Limit to 5 samples total
                    f.write(f"- {sample}\n")

            f.write("\n" + "-" * 50 + "\n")


def main():
    parser = argparse.ArgumentParser(description='Analyze XML and JSON schema structure from input files')
    parser.add_argument('--input', type=str, default='input',
                        help='Input directory containing XML and JSON files (default: input)')
    parser.add_argument('--output', type=str, default='output',
                        help='Output directory for analysis results (default: output)')

    args = parser.parse_args()

    input_dir = args.input
    output_dir = args.output

    print(f"Analyzing files in {input_dir}...")

    # Get input files
    files = get_input_files(input_dir)

    if not files:
        print(f"No XML or JSON files found in {input_dir}")
        return

    print(f"Found {len(files)} XML/JSON files to analyze")

    # Analyze each file
    results = []
    for i, file_path in enumerate(files):
        print(f"Analyzing file {i + 1}/{len(files)}: {os.path.basename(file_path)}")

        if file_path.lower().endswith('.xml'):
            result = analyze_xml_structure(file_path)
        elif file_path.lower().endswith('.json'):
            result = analyze_json_structure(file_path)
        else:
            continue

        results.append(result)

    # Generate summary
    summary = generate_summary(results)

    # Save results
    save_results(results, summary, output_dir)

    print(f"Analysis complete. Results saved to {output_dir}")
    print(f"  - Detailed results: {os.path.join(output_dir, 'schema_analysis_details.json')}")
    print(f"  - Summary: {os.path.join(output_dir, 'schema_analysis_summary.json')}")
    print(f"  - Human-readable report: {os.path.join(output_dir, 'schema_report.txt')}")


if __name__ == "__main__":
    main()