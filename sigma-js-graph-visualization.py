import sqlite3
import pandas as pd
import json
from tqdm import tqdm

# -----------------------------
# Configuration Options
# -----------------------------

# Specify which node types to plot (choose from "profile", "activity", "media")
selected_node_types = {"profile", "activity", "media"}

# Specify the minimum number of relationships (edges) a node must have to be included
min_relationships = 2

# Path to your SQLite database
db_path = 'output/social_network_anonymized.db'

# -----------------------------
# Vertex initialization
# -----------------------------
vertices = {}  # Dictionary of vertices with attributes
edges = []     # List of edges with attributes

# Connect to the database
conn = sqlite3.connect(db_path)

# --- Process Profiles ---
profiles_df = pd.read_sql_query("SELECT id, name, profile_type, platform, profile_url, region FROM Profiles", conn)
for _, row in tqdm(profiles_df.iterrows(), total=profiles_df.shape[0], desc="Processing Profiles"):
    node_id = f"profile_{row['id']}"
    vertices[node_id] = {
        "id": node_id,
        "label": row["name"],
        "type": "profile",
        "profile_type": row["profile_type"],
        "platform": row["platform"],
        "profile_url": row["profile_url"],
        "region": row["region"],
        "degree": 0  # Will count connections later
    }

# --- Process Activities ---
activity_df = pd.read_sql_query("SELECT id, type, timestamp, content, description, platform FROM Activity", conn)
for _, row in tqdm(activity_df.iterrows(), total=activity_df.shape[0], desc="Processing Activities"):
    node_id = f"activity_{row['id']}"
    vertices[node_id] = {
        "id": node_id,
        "label": f"Activity {row['id']}",
        "type": "activity",
        "activity_type": row["type"],
        "timestamp": row["timestamp"],
        "content": row["content"],
        "description": row["description"],
        "platform": row["platform"],
        "degree": 0  # Will count connections later
    }

# --- Process Media ---
media_df = pd.read_sql_query("SELECT id, type, file_reference, original_url FROM Media", conn)
for _, row in tqdm(media_df.iterrows(), total=media_df.shape[0], desc="Processing Media"):
    node_id = f"media_{row['id']}"
    vertices[node_id] = {
        "id": node_id,
        "label": f"Media {row['id']}",
        "type": "media",
        "media_type": row["type"],
        "file_reference": row["file_reference"],
        "original_url": row["original_url"],
        "degree": 0  # Will count connections later
    }

# --- Process Edges ---

# --- ProfileConnection edges (Profile-to-Profile) ---
profile_conn_df = pd.read_sql_query("SELECT source_id, target_id, connection_type FROM ProfileConnection", conn)
for _, row in tqdm(profile_conn_df.iterrows(), total=profile_conn_df.shape[0], desc="Processing Profile Connections"):
    source = f"profile_{row['source_id']}"
    target = f"profile_{row['target_id']}"
    if source in vertices and target in vertices:
        edge_id = f"{source}_{target}"
        edges.append({
            "id": edge_id,
            "source": source,
            "target": target,
            "type": row["connection_type"]
        })
        # Increment degree count
        vertices[source]["degree"] += 1
        vertices[target]["degree"] += 1

# --- ProfileActivity edges (Profile-to-Activity) ---
profile_activity_df = pd.read_sql_query("SELECT profile_id, activity_id, relationship_type FROM ProfileActivity", conn)
for _, row in tqdm(profile_activity_df.iterrows(), total=profile_activity_df.shape[0], desc="Processing Profile Activities"):
    source = f"profile_{row['profile_id']}"
    target = f"activity_{row['activity_id']}"
    if source in vertices and target in vertices:
        edge_id = f"{source}_{target}"
        edges.append({
            "id": edge_id,
            "source": source,
            "target": target,
            "type": row["relationship_type"]
        })
        # Increment degree count
        vertices[source]["degree"] += 1
        vertices[target]["degree"] += 1

# --- ActivityMedia edges (Activity-to-Media) ---
activity_media_df = pd.read_sql_query("SELECT activity_id, media_id, relationship_type FROM ActivityMedia", conn)
for _, row in tqdm(activity_media_df.iterrows(), total=activity_media_df.shape[0], desc="Processing Activity Media"):
    source = f"activity_{row['activity_id']}"
    target = f"media_{row['media_id']}"
    if source in vertices and target in vertices:
        edge_id = f"{source}_{target}"
        edges.append({
            "id": edge_id,
            "source": source,
            "target": target,
            "type": row["relationship_type"]
        })
        # Increment degree count
        vertices[source]["degree"] += 1
        vertices[target]["degree"] += 1

conn.close()

# Filter vertices by type and minimum relationships
filtered_vertices = {
    k: v for k, v in vertices.items() 
    if v["type"] in selected_node_types and v["degree"] >= min_relationships
}

# Filter edges to only include connections between filtered vertices
filtered_edges = [
    e for e in edges 
    if e["source"] in filtered_vertices and e["target"] in filtered_vertices
]

# Create final graph data structure for sigma.js
graph_data = {
    "nodes": list(filtered_vertices.values()),
    "edges": filtered_edges
}

# Save graph data as JSON for sigma.js
with open("filtered_social_network_for_sigmajs.json", "w") as f:
    json.dump(graph_data, f, indent=2)

print(f"Exported {len(filtered_vertices)} nodes and {len(filtered_edges)} edges for sigma.js")
