import sqlite3
import pandas as pd
from tqdm import tqdm
from igraph import Graph, plot

# -----------------------------
# Configuration: Specify which node types to plot.
# You can adjust the set below to include any combination of: "profile", "activity", "media"
selected_node_types = {"profile",}# "activity"}  
# -----------------------------

# Helper: maintain a mapping from our custom node IDs (strings) to igraph vertex indices.
vertex_dict = {}
vertices = []      # List of vertex names (our custom IDs)
vertex_attrs = []  # List of dictionaries with vertex attributes

def add_vertex(v_id, attr):
    """Adds a vertex if not already added, storing its attributes."""
    if v_id not in vertex_dict:
        index = len(vertices)
        vertex_dict[v_id] = index
        vertices.append(v_id)
        vertex_attrs.append(attr)

# Path to your SQLite database.
db_path = 'output/social_network_anonymized.db'

# Connect to the database.
conn = sqlite3.connect(db_path)

# -----------------------------
# Process Profiles into vertices.
# -----------------------------
profiles_df = pd.read_sql_query(
    "SELECT id, name, profile_type, platform, profile_url, region FROM Profiles", conn
)
for _, row in tqdm(profiles_df.iterrows(), total=profiles_df.shape[0], desc="Processing Profiles"):
    v_name = f"profile_{row['id']}"
    add_vertex(v_name, {
        "label": row["name"],
        "type": "profile",
        "profile_type": row["profile_type"],
        "platform": row["platform"],
        "profile_url": row["profile_url"],
        "region": row["region"]
    })

# -----------------------------
# Process Activities into vertices.
# -----------------------------
activity_df = pd.read_sql_query(
    "SELECT id, type, timestamp, content, description, platform FROM Activity", conn
)
for _, row in tqdm(activity_df.iterrows(), total=activity_df.shape[0], desc="Processing Activities"):
    v_name = f"activity_{row['id']}"
    add_vertex(v_name, {
        "type": "activity",
        "activity_type": row["type"],
        "timestamp": row["timestamp"],
        "content": row["content"],
        "description": row["description"],
        "platform": row["platform"]
    })

# -----------------------------
# Process Media into vertices.
# -----------------------------
media_df = pd.read_sql_query(
    "SELECT id, type, file_reference, original_url FROM Media", conn
)
for _, row in tqdm(media_df.iterrows(), total=media_df.shape[0], desc="Processing Media"):
    v_name = f"media_{row['id']}"
    add_vertex(v_name, {
        "type": "media",
        "media_type": row["type"],
        "file_reference": row["file_reference"],
        "original_url": row["original_url"]
    })

# Close the connection for vertex loading.
conn.close()

# -----------------------------
# Build the edge list.
# -----------------------------
edges = []      # List of tuples (source_index, target_index)
edge_attrs = [] # List of dictionaries for edge attributes

conn = sqlite3.connect(db_path)

# ProfileConnection edges (Profile-to-Profile)
profile_conn_df = pd.read_sql_query(
    "SELECT source_id, target_id, connection_type FROM ProfileConnection", conn
)
for _, row in tqdm(profile_conn_df.iterrows(), total=profile_conn_df.shape[0], desc="Processing Profile Connections"):
    source = f"profile_{row['source_id']}"
    target = f"profile_{row['target_id']}"
    if source in vertex_dict and target in vertex_dict:
        edges.append((vertex_dict[source], vertex_dict[target]))
        edge_attrs.append({"type": row["connection_type"]})

# ProfileActivity edges (Profile-to-Activity)
profile_activity_df = pd.read_sql_query(
    "SELECT profile_id, activity_id, relationship_type FROM ProfileActivity", conn
)
for _, row in tqdm(profile_activity_df.iterrows(), total=profile_activity_df.shape[0], desc="Processing Profile Activities"):
    source = f"profile_{row['profile_id']}"
    target = f"activity_{row['activity_id']}"
    if source in vertex_dict and target in vertex_dict:
        edges.append((vertex_dict[source], vertex_dict[target]))
        edge_attrs.append({"type": row["relationship_type"]})

# ActivityMedia edges (Activity-to-Media)
activity_media_df = pd.read_sql_query(
    "SELECT activity_id, media_id, relationship_type FROM ActivityMedia", conn
)
for _, row in tqdm(activity_media_df.iterrows(), total=activity_media_df.shape[0], desc="Processing Activity Media"):
    source = f"activity_{row['activity_id']}"
    target = f"media_{row['media_id']}"
    if source in vertex_dict and target in vertex_dict:
        edges.append((vertex_dict[source], vertex_dict[target]))
        edge_attrs.append({"type": row["relationship_type"]})

conn.close()

# -----------------------------
# Build the igraph Graph.
# -----------------------------
g = Graph()
g.add_vertices(len(vertices))
g.vs["name"] = vertices  # Assign vertex names

# Set vertex attributes.
all_vertex_keys = set()
for attr in vertex_attrs:
    all_vertex_keys.update(attr.keys())
for key in all_vertex_keys:
    g.vs[key] = [attr.get(key, None) for attr in vertex_attrs]

g.add_edges(edges)

# Set edge attributes.
all_edge_keys = set()
for attr in edge_attrs:
    all_edge_keys.update(attr.keys())
for key in all_edge_keys:
    g.es[key] = [attr.get(key, None) for attr in edge_attrs]

# -----------------------------
# Filter the graph to only include selected node types.
# -----------------------------
selected_indices = [v.index for v in g.vs if v["type"] in selected_node_types]
subgraph = g.induced_subgraph(selected_indices)

# -----------------------------
# Compute the layout using igraph's Fruchterman-Reingold algorithm.
# -----------------------------
layout = subgraph.layout("fr")

# Optionally set vertex colors based on type.
color_map = {"profile": "skyblue", "activity": "lightgreen", "media": "lightcoral"}
vertex_colors = [color_map.get(v["type"], "grey") for v in subgraph.vs]

# -----------------------------
# Plot the subgraph.
# -----------------------------
graph = plot(
    subgraph,
    layout=layout,
    vertex_color=vertex_colors,
    vertex_label=subgraph.vs["name"],
    margin=40,
    bbox=(8000, 8000),
    target="social_network.png"
)

# Save the graph (or subgraph) to a GraphML file.
subgraph.write_graphml("social_network.graphml")

