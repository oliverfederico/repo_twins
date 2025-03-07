#!/usr/bin/env python3
import sqlite3
import argparse
import os
import json
from pathlib import Path


def export_sqlite_info(db_path="output/social_network_anonymized.db", num_lines=3, output_format="text"):
    """
    Export schema and first N lines of data from all tables in an SQLite database.

    Args:
        db_path (str): Path to the SQLite database file
        nuam_lines (int): Number of lines to export from each table
        output_format (str): Format for output ('text' or 'json')

    Returns:
        dict: Results containing schema and data information if format is 'json'
        Otherwise prints to stdout
    """
    # Check if the database file exists
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database file not found: {db_path}")

    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Dictionary to store all results
    results = {
        "database": db_path,
        "tables": {}
    }

    # Get list of tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [table[0] for table in cursor.fetchall() if not table[0].startswith('sqlite_')]

    for table in tables:
        table_info = {
            "schema": [],
            "data": []
        }

        # Get table schema
        cursor.execute(f"PRAGMA table_info({table});")
        columns_info = cursor.fetchall()

        # Format schema information
        for col in columns_info:
            # col format: (cid, name, type, notnull, default_value, pk)
            col_info = {
                "cid": col[0],
                "name": col[1],
                "type": col[2],
                "notnull": bool(col[3]),
                "default_value": col[4],
                "primary_key": bool(col[5])
            }
            table_info["schema"].append(col_info)

        # Get the first N rows of data
        try:
            cursor.execute(f"SELECT * FROM {table} LIMIT {num_lines};")
            rows = cursor.fetchall()

            # Get column names
            column_names = [description[0] for description in cursor.description]

            # Format row data
            for row in rows:
                row_data = {}
                for i, value in enumerate(row):
                    col_name = column_names[i]
                    # Include the data type of each value
                    data_type = type(value).__name__ if value is not None else "NULL"
                    row_data[col_name] = {
                        "value": value,
                        "type": data_type
                    }
                table_info["data"].append(row_data)

        except sqlite3.Error as e:
            table_info["error"] = str(e)

        results["tables"][table] = table_info

    # Close the connection
    conn.close()

    # Output results based on format
    if output_format == "json":
        return results
    else:
        # Text output
        print(f"Database: {db_path}\n")

        for table_name, table_data in results["tables"].items():
            print(f"Table: {table_name}")
            print("=" * 50)

            # Print schema
            print("Schema:")
            print("-" * 50)
            header = "CID | Name | Type | NotNull | Default | PK"
            print(header)
            print("-" * len(header))

            for col in table_data["schema"]:
                print(f"{col['cid']} | {col['name']} | {col['type']} | "
                      f"{col['notnull']} | {col['default_value']} | {col['primary_key']}")

            # Print data
            print("\nData:")
            print("-" * 50)

            if "error" in table_data:
                print(f"Error reading data: {table_data['error']}")
            elif not table_data["data"]:
                print("No data in table")
            else:
                # Get all column names
                columns = [col["name"] for col in table_data["schema"]]

                # Print column headers
                print(" | ".join(columns))
                print("-" * 50)

                # Print rows
                for row in table_data["data"]:
                    row_values = []
                    for col in columns:
                        if col in row:
                            value = row[col]["value"]
                            data_type = row[col]["type"]
                            formatted_value = f"{value} ({data_type})" if value is not None else "NULL"
                        else:
                            formatted_value = "NULL"
                        row_values.append(str(formatted_value))
                    print(" | ".join(row_values))

            print("\n")

    return results


def main():
    parser = argparse.ArgumentParser(description='Export SQLite database schema and sample data')
    parser.add_argument('--db', type=str, default='output/social_network_anonymized.db',
                        help='Path to SQLite database file (default: social_network_db.sqlite in current directory)')
    parser.add_argument('--lines', type=int, default=3,
                        help='Number of data lines to export from each table (default: 3)')
    parser.add_argument('--format', type=str, choices=['text', 'json'], default='text',
                        help='Output format: text or json (default: text)')
    parser.add_argument('--output', type=str, default=None,
                        help='Output file path (if not specified, prints to stdout)')

    args = parser.parse_args()

    try:
        results = export_sqlite_info(args.db, args.lines, args.format)

        # If output file is specified
        if args.output and args.format == 'json':
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {args.output}")
        elif args.output and args.format == 'text':
            # Redirect stdout to file is handled elsewhere when using text format
            print(f"For text format with file output, use: python script.py --format text > output.txt")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()