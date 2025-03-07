import argparse
import ast
import datetime
import hashlib
import json
import logging
import mimetypes
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any

from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('reposcout')

# Constants
DEFAULT_MAX_FILE_SIZE = 4096 * 1024  # 1MB
DEFAULT_MAX_TOTAL_TOKENS = 200000
DEFAULT_EXCLUDE_PATTERNS = [
    # Directories to exclude - with anchored patterns that work more reliably
    r'(^|/)\.git($|/)', r'(^|/)\.venv($|/)', r'(^|/)venv($|/)',
    r'(^|/)__pycache__($|/)', r'(^|/)\.pytest_cache($|/)',
    r'(^|/)node_modules($|/)', r'(^|/)\.ida($|/)', r'(^|/)\.vscode($|/)',
    r'(^|/)\.idea($|/)',

    # Files to exclude
    r'\.DS_Store$',
    r'\.jpg$', r'\.jpeg$', r'\.png$', r'\.gif$', r'\.ico$', r'\.svg$',
    r'\.pdf$', r'\.zip$', r'\.tar$', r'\.gz$', r'\.rar$',
    r'\.pyc$', r'\.pyo$', r'\.pyd$', r'\.so$', r'\.dll$', r'\.exe$',
    r'\.whl$', r'\.jar$', r'\.class$',
    r'\.log$', r'\.db$', r'\.sqlite$', r'\.sqlite3$', r'\.md$',

    # Reposcout and coderbot exclusions
    r'reposcout', r'coderbot', r'param_benchmark.py', r'repoclean.py'  # Match anywhere in path
]
# Default file extensions to show in outline but not include contents
DEFAULT_OUTLINE_ONLY_EXTENSIONS = ['.json', '.xml', '.csv', '.html']
DEFAULT_EXTENSION_PRIORITIES = {
    '.md': 100,  # Documentation
    '.rst': 100,
    '.py': 90,  # Python source
    '.js': 85,  # JavaScript source
    '.ts': 85,  # TypeScript source
    '.jsx': 85,
    '.tsx': 85,
    '.go': 85,  # Golang source
    '.java': 85,  # Java source
    '.c': 85,  # C source
    '.cpp': 85,  # C++ source
    '.h': 85,  # Header files
    '.rb': 85,  # Ruby source
    '.php': 85,  # PHP source
    '.toml': 80,  # Config files
    '.yaml': 80,
    '.yml': 80,
    '.json': 80,
    '.xml': 80,
    '.ini': 80,
    '.cfg': 80,
    '.env': 70,  # Environment variables
    '.css': 60,  # Style files
    '.scss': 60,
    '.html': 60,  # Templates
    '.jinja': 60,
    '.jinja2': 60,
    '.txt': 50,  # Text files
    '.sql': 50,  # SQL
    '.sh': 50,  # Shell scripts
    '.bat': 50,  # Batch files
    '.ps1': 50,  # PowerShell
    '.csv': 40,  # Data files
    '.tsv': 40,
    '.lock': 30,  # Lock files
}
DEFAULT_FILENAME_PRIORITIES = {
    'readme': 100,
    'license': 95,
    'dockerfile': 90,
    'docker-compose': 90,
    'requirements.txt': 90,
    'package.json': 90,
    'setup.py': 90,
    'pyproject.toml': 90,
    'main': 85,
    'app': 85,
    'index': 85,
    'server': 85,
    'client': 85,
    'config': 80,
    'settings': 80,
    'constants': 80,
    'utils': 75,
    'helpers': 75,
    'tests': 70,
    'test': 70,
}
DEFAULT_MAX_SAMPLES = 5
DEFAULT_MAX_LINES_PER_FILE = 4000
DEFAULT_TREE_MAX_DEPTH = 5


@dataclass
class FileInfo:
    """Information about a file in the repository."""
    path: str
    rel_path: str
    mime_type: Optional[str] = None
    extension: str = ''
    size: int = 0
    lines: int = 0
    chars: int = 0
    content: Optional[str] = None
    content_hash: Optional[str] = None
    importance_score: float = 0.0
    imports: List[str] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    summary: Optional[str] = None
    sampled: bool = False
    is_test: bool = False
    error: Optional[str] = None
    outline_only: bool = False  # Flag to indicate if file should be in outline only

    def to_dict(self):
        """Convert to dictionary, excluding the content field."""
        result = asdict(self)
        result.pop('content', None)
        return result


@dataclass
class RepositoryInfo:
    """Information about the entire repository."""
    path: str
    files: List[FileInfo] = field(default_factory=list)
    dirs: List[str] = field(default_factory=list)
    file_count: int = 0
    dir_count: int = 0
    total_size: int = 0
    total_lines: int = 0
    languages: Dict[str, int] = field(default_factory=dict)
    entry_points: List[str] = field(default_factory=list)
    dependencies: Dict[str, List[str]] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    config: Dict[str, Any] = field(default_factory=dict)


class RepoScout:
    """Advanced repository analysis tool optimized for LLM consumption."""

    def __init__(self, config=None):
        """Initialize with configuration options."""
        self.config = {
            'source_dir': '.',
            'output_file': None,
            'output_format': 'markdown',
            'max_file_size': DEFAULT_MAX_FILE_SIZE,
            'max_total_tokens': DEFAULT_MAX_TOTAL_TOKENS,
            'exclude_patterns': DEFAULT_EXCLUDE_PATTERNS,
            'outline_only_extensions': DEFAULT_OUTLINE_ONLY_EXTENSIONS,  # New option
            'extension_priorities': DEFAULT_EXTENSION_PRIORITIES,
            'filename_priorities': DEFAULT_FILENAME_PRIORITIES,
            'include_content': True,
            'summarize_large_files': True,
            'max_samples': DEFAULT_MAX_SAMPLES,
            'max_lines_per_file': DEFAULT_MAX_LINES_PER_FILE,
            'parallel': True,
            'tree_max_depth': DEFAULT_TREE_MAX_DEPTH,
            'verbose': False,
            'token_ratio': 4.0,  # Estimated chars per token
        }

        if config:
            self.config.update(config)

        if self.config['verbose']:
            logger.setLevel(logging.DEBUG)

        if not self.config['output_file']:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.config['output_file'] = f"reposcout_{timestamp}.{self.config['output_format']}"

        # Always exclude the current output file
        if self.config['output_file']:
            output_filename = os.path.basename(self.config['output_file'])
            self.config['exclude_patterns'].append(re.escape(output_filename) + '$')

    def _is_excluded(self, path):
        """Check if path matches any exclude pattern."""
        # Convert to relative path consistently
        if os.path.isabs(path) or path.startswith(self.config['source_dir']):
            rel_path = os.path.relpath(path, self.config['source_dir'])
        else:
            rel_path = path

        for pattern in self.config['exclude_patterns']:
            if re.search(pattern, rel_path):
                return True
        return False

    def _is_outline_only(self, file_path):
        """Check if file should be in outline only (no content inclusion)."""
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.config['outline_only_extensions']

    def _get_file_type(self, file_path):
        """Determine the MIME type of a file."""
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type

    def _is_text_file(self, file_path, mime_type=None):
        """Check if file is a text file."""
        if not mime_type:
            mime_type = self._get_file_type(file_path)

        # Common text file MIME types
        if mime_type is None:
            # Try to read the first few bytes to check if it's text
            try:
                with open(file_path, 'rb') as f:
                    sample = f.read(1024)
                    # Check if the sample contains mostly ASCII characters
                    text_characters = bytes(range(32, 127)) + b'\n\r\t\b'
                    return not bool(sample.translate(None, text_characters))
            except Exception:
                return False

        return (mime_type is None or
                mime_type.startswith('text') or
                mime_type in [
                    'application/json',
                    'application/javascript',
                    'application/xml',
                    'application/x-shellscript',
                    'application/x-python-code',
                    'application/x-ruby',
                    'application/x-yaml',
                ])

    def _count_lines_and_chars(self, file_path):
        """Count lines and characters in a file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                return len(content.splitlines()), len(content), content
        except Exception as e:
            logger.warning(f"Error reading {file_path}: {str(e)}")
            return 0, 0, None

    def _calculate_importance_score(self, file_info):
        """Calculate importance score for a file based on multiple factors."""
        score = 0.0

        # Extension priority
        ext_priority = self.config['extension_priorities'].get(file_info.extension.lower(), 0)
        score += ext_priority * 0.5  # Extension is a strong factor

        # Filename priority
        filename = os.path.basename(file_info.path).lower()
        filename_no_ext = os.path.splitext(filename)[0]

        for name, priority in self.config['filename_priorities'].items():
            if name.lower() in filename_no_ext.lower():
                score += priority * 0.4
                break

        # Location priority - files at the root are often more important
        depth = len(file_info.rel_path.split(os.sep)) - 1
        score += max(0, 50 - (depth * 10)) * 0.1  # Deprioritize deeply nested files

        # Is it a test file?
        if '/test' in file_info.rel_path.lower() or file_info.rel_path.lower().startswith(
                'test') or '_test' in filename_no_ext.lower():
            file_info.is_test = True
            score *= 0.7  # Deprioritize test files slightly

        # Size factor - penalize very large files but also very tiny ones
        if file_info.size > 0:
            size_factor = min(1.0, file_info.size / 50000)  # Files around ~50KB get max score
            if file_info.size > 100000:  # Penalize very large files
                size_factor *= 0.5
            score *= (0.5 + size_factor * 0.5)  # Size has moderate impact

        # Consider the number of imports/functions/classes for code files
        if len(file_info.imports) > 0 or len(file_info.functions) > 0 or len(file_info.classes) > 0:
            complexity = min(1.0,
                             (len(file_info.imports) + len(file_info.functions) * 2 + len(file_info.classes) * 3) / 20)
            score *= (0.7 + complexity * 0.3)

        return round(score, 2)

    def _analyze_python_file(self, content):
        """Extract imports, classes, and functions from Python file."""
        imports = []
        classes = []
        functions = []

        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        imports.append(name.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        for name in node.names:
                            imports.append(f"{node.module}.{name.name}")
                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                elif isinstance(node, ast.FunctionDef):
                    functions.append(node.name)
        except SyntaxError:
            # Not valid Python or using newer syntax
            pass

        return imports, classes, functions

    def _analyze_javascript_file(self, content):
        """Basic analysis of JavaScript/TypeScript files using regex."""
        imports = []
        classes = []
        functions = []

        # Extract imports
        import_patterns = [
            r'import\s+{([^}]+)}\s+from\s+[\'"]([^\'"]+)[\'"]',  # import { a, b } from 'module'
            r'import\s+(\w+)\s+from\s+[\'"]([^\'"]+)[\'"]',  # import a from 'module'
            r'import\s+[\'"]([^\'"]+)[\'"]',  # import 'module'
            r'require\([\'"]([^\'"]+)[\'"]\)'  # require('module')
        ]

        for pattern in import_patterns:
            for match in re.finditer(pattern, content):
                if '{' in pattern:
                    imports.extend([m.strip() for m in match.group(1).split(',')])
                    imports.append(match.group(2))
                elif 'require' in pattern or 'import' in pattern and 'from' not in pattern:
                    imports.append(match.group(1))
                else:
                    imports.append(f"{match.group(1)} from {match.group(2)}")

        # Extract classes
        class_pattern = r'class\s+(\w+)'
        classes = [match.group(1) for match in re.finditer(class_pattern, content)]

        # Extract functions
        function_patterns = [
            r'function\s+(\w+)\s*\(',  # function name()
            r'(\w+)\s*:\s*function\s*\(',  # name: function()
            r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>'  # const name = () =>
        ]

        for pattern in function_patterns:
            for match in re.finditer(pattern, content):
                functions.append(match.group(1))

        return list(set(imports)), list(set(classes)), list(set(functions))

    def _analyze_file_by_type(self, file_info):
        """Analyze file based on its type."""
        if not file_info.content:
            return

        ext = file_info.extension.lower()
        if ext == '.py':
            imports, classes, functions = self._analyze_python_file(file_info.content)
            file_info.imports = imports
            file_info.classes = classes
            file_info.functions = functions
        elif ext in ['.js', '.jsx', '.ts', '.tsx']:
            imports, classes, functions = self._analyze_javascript_file(file_info.content)
            file_info.imports = imports
            file_info.classes = classes
            file_info.functions = functions

    def _summarize_file(self, file_info):
        """Generate a summary for a file."""
        if not file_info.content:
            return

        # For now, simple approach: extract key components and first few lines
        summary_parts = []

        # Add file info
        summary_parts.append(f"Path: {file_info.rel_path}")
        summary_parts.append(f"Size: {file_info.size:,} bytes, Lines: {file_info.lines}")

        # Add key components based on file type
        if file_info.classes:
            summary_parts.append(f"Classes: {', '.join(file_info.classes[:10])}")
            if len(file_info.classes) > 10:
                summary_parts[-1] += f" and {len(file_info.classes) - 10} more"

        if file_info.functions:
            summary_parts.append(f"Functions: {', '.join(file_info.functions[:10])}")
            if len(file_info.functions) > 10:
                summary_parts[-1] += f" and {len(file_info.functions) - 10} more"

        if file_info.imports:
            summary_parts.append(f"Imports: {', '.join(file_info.imports[:10])}")
            if len(file_info.imports) > 10:
                summary_parts[-1] += f" and {len(file_info.imports) - 10} more"

        # Add first few lines as a preview
        lines = file_info.content.splitlines()
        if lines:
            preview_lines = [line for line in lines[:10] if line.strip()]
            if preview_lines:
                summary_parts.append("Preview:")
                summary_parts.append("\n".join(preview_lines))
                if len(lines) > 10:
                    summary_parts.append(f"... {len(lines) - 10} more lines ...")

        file_info.summary = "\n".join(summary_parts)

    def _process_file(self, file_path):
        """Process a single file."""
        try:
            rel_path = os.path.relpath(file_path, self.config['source_dir'])

            # Skip excluded files
            if self._is_excluded(rel_path):
                logger.debug(f"Skipping excluded file: {rel_path}")
                return None

            # Get basic file information
            size = os.path.getsize(file_path)
            mime_type = self._get_file_type(file_path)
            extension = os.path.splitext(file_path)[1]

            # Check if this file should be in outline only
            outline_only = self._is_outline_only(file_path)

            # Create basic file info for outline-only files
            if outline_only:
                file_info = FileInfo(
                    path=file_path,
                    rel_path=rel_path,
                    mime_type=mime_type,
                    extension=extension,
                    size=size,
                    outline_only=True
                )
                file_info.importance_score = self._calculate_importance_score(file_info)
                return file_info

            # Check if it's a text file
            if not self._is_text_file(file_path, mime_type) or size > self.config['max_file_size']:
                logger.debug(f"Skipping non-text or large file: {rel_path}")
                file_info = FileInfo(
                    path=file_path,
                    rel_path=rel_path,
                    mime_type=mime_type,
                    extension=extension,
                    size=size
                )
                self._calculate_importance_score(file_info)
                return file_info

            # Count lines and get content
            lines, chars, content = self._count_lines_and_chars(file_path)

            # Create file hash
            content_hash = None
            if content:
                content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

            # Create file info object
            file_info = FileInfo(
                path=file_path,
                rel_path=rel_path,
                mime_type=mime_type,
                extension=extension,
                size=size,
                lines=lines,
                chars=chars,
                content=content,
                content_hash=content_hash
            )

            # Analyze file content
            if content:
                self._analyze_file_by_type(file_info)

                # Check if we need to summarize instead of keeping full content
                if (lines > self.config['max_lines_per_file'] and self.config['summarize_large_files']):
                    self._summarize_file(file_info)
                    file_info.sampled = True

            # Calculate importance score
            file_info.importance_score = self._calculate_importance_score(file_info)

            return file_info

        except Exception as e:
            logger.error(f"Error processing {file_path}: {str(e)}")
            return FileInfo(
                path=file_path,
                rel_path=os.path.relpath(file_path, self.config['source_dir']),
                error=str(e)
            )

    def _collect_files(self):
        """Collect all files in the repository."""
        repo_files = []
        repo_dirs = []

        for root, dirs, files in os.walk(self.config['source_dir']):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]

            rel_root = os.path.relpath(root, self.config['source_dir'])
            if rel_root != '.':
                repo_dirs.append(rel_root)

            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.config['source_dir'])

                if not self._is_excluded(rel_path):
                    repo_files.append(file_path)

        return repo_files, repo_dirs

    def _generate_directory_tree(self, max_depth=None):
        """Generate a directory tree with limited depth."""
        if max_depth is None:
            max_depth = self.config['tree_max_depth']

        tree_lines = []

        # Process all directories and files
        for root, dirs, files in os.walk(self.config['source_dir']):
            # Exclude directories from being traversed
            dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]

            # Calculate the level (depth) of the current directory
            rel_path = os.path.relpath(root, self.config['source_dir'])
            level = 0 if rel_path == '.' else rel_path.count(os.sep) + 1

            # Skip if we've reached max depth
            if max_depth is not None and level > max_depth:
                continue

            # Skip excluded directories (except the root)
            if rel_path != '.' and self._is_excluded(rel_path):
                continue

            # Add this directory to the tree
            if rel_path == '.':
                tree_lines.append("└─ ./")
            else:
                indent = '  ' * level
                tree_lines.append(f"{indent}└─ {os.path.basename(root)}/")

            # Sort and filter files
            sorted_files = sorted(files, key=lambda f: os.path.splitext(f)[1])
            included_files = []

            for file in sorted_files:
                file_path = os.path.join(root, file)
                rel_file_path = os.path.relpath(file_path, self.config['source_dir'])
                if not self._is_excluded(rel_file_path):
                    included_files.append(file)

            # Add files to the tree
            file_level = level + 1
            file_indent = '  ' * file_level
            for i, file in enumerate(included_files):
                prefix = '└─ ' if i == len(included_files) - 1 else '├─ '
                tree_lines.append(f"{file_indent}{prefix}{file}")

            # Add ellipsis if there are too many files
            if len(included_files) > 50:
                tree_lines.append(f"{file_indent}└─ ... ({len(included_files) - 50} more files)")

        return '\n'.join(tree_lines)

    def _detect_entrypoints(self, files):
        """Detect possible entry points to the application."""
        entry_points = []

        # Common entry point patterns
        entry_patterns = [
            (r'main\.py$', 'Python main module'),
            (r'app\.py$', 'Python app module'),
            (r'server\.py$', 'Python server module'),
            (r'manage\.py$', 'Django management script'),
            (r'wsgi\.py$', 'WSGI application'),
            (r'asgi\.py$', 'ASGI application'),
            (r'index\.(js|ts)$', 'JavaScript/TypeScript entry'),
            (r'server\.(js|ts)$', 'JavaScript/TypeScript server'),
            (r'main\.(go|rs|java|rb)$', 'Main program file'),
            (r'Dockerfile$', 'Docker build file'),
            (r'docker-compose\.ya?ml$', 'Docker Compose file')
        ]

        for file_info in files:
            for pattern, desc in entry_patterns:
                if re.search(pattern, file_info.rel_path, re.IGNORECASE):
                    entry_points.append((file_info.rel_path, desc))
                    break

        return entry_points

    def _detect_language_distribution(self, files):
        """Detect language distribution in the repository."""
        languages = {}

        # Extension to language mapping
        ext_to_lang = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.jsx': 'JavaScript (React)',
            '.ts': 'TypeScript',
            '.tsx': 'TypeScript (React)',
            '.go': 'Go',
            '.java': 'Java',
            '.c': 'C',
            '.cpp': 'C++',
            '.h': 'C/C++ Header',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.cs': 'C#',
            '.html': 'HTML',
            '.css': 'CSS',
            '.scss': 'SCSS',
            '.md': 'Markdown',
            '.rst': 'reStructuredText',
            '.json': 'JSON',
            '.xml': 'XML',
            '.yaml': 'YAML',
            '.yml': 'YAML',
            '.toml': 'TOML',
            '.sql': 'SQL',
            '.sh': 'Shell',
            '.bat': 'Batch',
            '.ps1': 'PowerShell',
        }

        for file_info in files:
            if file_info.extension.lower() in ext_to_lang:
                lang = ext_to_lang[file_info.extension.lower()]
                if lang in languages:
                    languages[lang] += file_info.lines
                else:
                    languages[lang] = file_info.lines

        # Sort by line count
        return dict(sorted(languages.items(), key=lambda x: x[1], reverse=True))

    def _build_dependency_graph(self, files):
        """Build a basic dependency graph from imports."""
        dependencies = {}
        file_by_path = {file_info.rel_path: file_info for file_info in files}

        # Map module names to file paths (simplified)
        module_to_path = {}
        for rel_path, file_info in file_by_path.items():
            module_name = os.path.splitext(rel_path)[0].replace(os.sep, '.')
            module_to_path[module_name] = rel_path

            # Also add the basename without extension
            base_name = os.path.splitext(os.path.basename(rel_path))[0]
            module_to_path[base_name] = rel_path

        # Build dependencies
        for file_info in files:
            if file_info.imports:
                importing_file = file_info.rel_path
                dependencies[importing_file] = []

                for imp in file_info.imports:
                    # Extract the base module name (before the dot)
                    base_module = imp.split('.')[0]

                    # Skip standard library or external packages
                    if base_module in sys.builtin_module_names:
                        continue

                    # Check if this import references another file in the repo
                    if base_module in module_to_path:
                        dependencies[importing_file].append(module_to_path[base_module])

        return dependencies

    def _process_files_parallel(self, file_paths):
        """Process files in parallel using a process pool."""
        processed_files = []

        with ProcessPoolExecutor() as executor:
            futures = {executor.submit(self._process_file, path): path for path in file_paths}

            with tqdm(total=len(futures), desc="Processing files", disable=not self.config['verbose']) as pbar:
                for future in as_completed(futures):
                    file_info = future.result()
                    if file_info:
                        processed_files.append(file_info)
                    pbar.update(1)

        return processed_files

    def _process_files_sequential(self, file_paths):
        """Process files sequentially."""
        processed_files = []

        for path in tqdm(file_paths, desc="Processing files", disable=not self.config['verbose']):
            file_info = self._process_file(path)
            if file_info:
                processed_files.append(file_info)

        return processed_files

    def _prioritize_and_sample(self, files):
        """Prioritize files and sample them to fit token budget."""
        # First, sort by importance score
        files.sort(key=lambda x: x.importance_score, reverse=True)

        # Estimate tokens
        estimated_tokens = 0
        files_to_include = []

        for file_info in files:
            # Skip outline-only files for content inclusion
            if file_info.outline_only:
                files_to_include.append(file_info)
                continue

            if file_info.content:
                content_tokens = len(file_info.content) / self.config['token_ratio']

                # Check if we exceeded the token budget
                if estimated_tokens + content_tokens > self.config['max_total_tokens']:
                    # If this is a high-importance file, generate a summary instead
                    if file_info.importance_score > 50 and self.config['summarize_large_files']:
                        self._summarize_file(file_info)
                        file_info.sampled = True
                        file_info.content = None  # Remove content to save memory
                        summary_tokens = len(file_info.summary) / self.config['token_ratio']
                        estimated_tokens += summary_tokens
                        files_to_include.append(file_info)
                else:
                    estimated_tokens += content_tokens
                    files_to_include.append(file_info)
            else:
                # Files without content (binary, etc.) are included with minimal token cost
                files_to_include.append(file_info)

        return files_to_include

    def analyze(self):
        """Analyze the repository and return repository info."""
        logger.info(f"Analyzing repository: {self.config['source_dir']}")

        # Collect all files
        file_paths, dirs = self._collect_files()
        logger.info(f"Found {len(file_paths)} files in {len(dirs)} directories")

        # Process files
        if self.config['parallel'] and len(file_paths) > 10:
            files = self._process_files_parallel(file_paths)
        else:
            files = self._process_files_sequential(file_paths)

        # Calculate repository statistics
        total_size = sum(f.size for f in files)
        total_lines = sum(f.lines for f in files)

        # Prioritize and sample files
        included_files = self._prioritize_and_sample(files)

        # Detect entry points
        entry_points = self._detect_entrypoints(files)

        # Detect language distribution
        languages = self._detect_language_distribution(files)

        # Build dependency graph
        dependencies = self._build_dependency_graph(files)

        # Create repository info
        repo_info = RepositoryInfo(
            path=self.config['source_dir'],
            files=included_files,
            dirs=dirs,
            file_count=len(file_paths),
            dir_count=len(dirs),
            total_size=total_size,
            total_lines=total_lines,
            languages=languages,
            entry_points=entry_points,
            dependencies=dependencies,
            config=self.config
        )

        logger.info(f"Repository analysis complete: {len(included_files)} files included in output")
        return repo_info

    def _format_markdown(self, repo_info):
        """Format repository info as Markdown."""
        lines = []
        lines.append(f"# Repository Analysis: {os.path.basename(repo_info.path)}")
        lines.append(f"Generated by RepoScout on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Summary section
        lines.append("## Repository Summary")
        lines.append(f"- **Files**: {repo_info.file_count:,}")
        lines.append(f"- **Directories**: {repo_info.dir_count:,}")
        lines.append(f"- **Total Size**: {repo_info.total_size:,} bytes ({repo_info.total_size / 1024 / 1024:.2f} MB)")
        lines.append(f"- **Total Lines**: {repo_info.total_lines:,}")
        lines.append("")

        # Language distribution
        if repo_info.languages:
            lines.append("## Language Distribution")
            lines.append("| Language | Lines | Percentage |")
            lines.append("|----------|-------|------------|")
            for lang, count in repo_info.languages.items():
                percentage = count / repo_info.total_lines * 100 if repo_info.total_lines > 0 else 0
                lines.append(f"| {lang} | {count:,} | {percentage:.1f}% |")
            lines.append("")

        # Entry points
        if repo_info.entry_points:
            lines.append("## Entry Points")
            for path, desc in repo_info.entry_points:
                lines.append(f"- **{path}**: {desc}")
            lines.append("")

        # Directory structure
        lines.append("## Directory Structure")
        lines.append("```")
        lines.append(self._generate_directory_tree())
        lines.append("```")
        lines.append("")

        # Key files
        lines.append("## Key Files")
        high_importance = [f for f in repo_info.files if f.importance_score >= 70 and not f.outline_only]
        high_importance.sort(key=lambda x: x.importance_score, reverse=True)

        for file_info in high_importance[:10]:
            lines.append(f"### {file_info.rel_path} (Score: {file_info.importance_score})")
            lines.append(f"- **Size**: {file_info.size:,} bytes")
            lines.append(f"- **Lines**: {file_info.lines:,}")

            if file_info.classes:
                lines.append(f"- **Classes**: {', '.join(file_info.classes[:5])}")
                if len(file_info.classes) > 5:
                    lines.append(f"  - *...and {len(file_info.classes) - 5} more*")

            if file_info.functions:
                lines.append(f"- **Functions**: {', '.join(file_info.functions[:5])}")
                if len(file_info.functions) > 5:
                    lines.append(f"  - *...and {len(file_info.functions) - 5} more*")

            lines.append("")

            # Display content for very important files
            if file_info.content and file_info.importance_score >= 80:
                lines.append("```" + file_info.extension[1:] if file_info.extension else "")
                # Limit content to ~50 lines for display
                content_lines = file_info.content.splitlines()
                if len(content_lines) > 50:
                    shown_content = "\n".join(content_lines[:50])
                    lines.append(shown_content)
                    lines.append(f"... ({len(content_lines) - 50} more lines)")
                else:
                    lines.append(file_info.content)
                lines.append("```")
                lines.append("")

        # File contents
        lines.append("## File Contents")

        included_files = [f for f in repo_info.files if f.content and not f.outline_only]
        included_files.sort(key=lambda x: x.importance_score, reverse=True)

        for file_info in included_files:
            lines.append(f"### {file_info.rel_path}")

            if file_info.sampled and file_info.summary:
                lines.append("*File was sampled due to size constraints*")
                lines.append("")
                lines.append(file_info.summary)
            elif file_info.content:
                lines.append("```" + file_info.extension[1:] if file_info.extension else "")
                lines.append(file_info.content)
                lines.append("```")

            lines.append("")

        return "\n".join(lines)

    def _format_json(self, repo_info):
        """Format repository info as JSON."""
        # Convert to dict, excluding file contents for better readability
        repo_dict = {
            "path": repo_info.path,
            "file_count": repo_info.file_count,
            "dir_count": repo_info.dir_count,
            "total_size": repo_info.total_size,
            "total_lines": repo_info.total_lines,
            "languages": repo_info.languages,
            "entry_points": repo_info.entry_points,
            "dependencies": repo_info.dependencies,
            "timestamp": repo_info.timestamp,
            "files": [file_info.to_dict() for file_info in repo_info.files],
            "dirs": repo_info.dirs,
            "config": repo_info.config
        }

        return json.dumps(repo_dict, indent=2)

    def export(self, repo_info=None):
        """Export repository analysis to the configured format."""
        if not repo_info:
            repo_info = self.analyze()

        output_format = self.config['output_format'].lower()

        if output_format == 'markdown' or output_format == 'md':
            content = self._format_markdown(repo_info)
        elif output_format == 'json':
            content = self._format_json(repo_info)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

        # Write to output file
        with open(self.config['output_file'], 'w', encoding='utf-8') as f:
            f.write(content)

        logger.info(f"Repository analysis exported to {self.config['output_file']}")
        return repo_info, self.config['output_file']


def main():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="RepoScout - Advanced repository analysis for LLMs")

    parser.add_argument('source_dir', nargs='?', default='.',
                        help='Repository directory to analyze (default: current directory)')
    parser.add_argument('-o', '--output', dest='output_file',
                        help='Output file (default: reposcout_TIMESTAMP.{format})')
    parser.add_argument('-f', '--format', dest='output_format', choices=['markdown', 'md', 'json'],
                        default='markdown', help='Output format (default: markdown)')
    parser.add_argument('--max-file-size', dest='max_file_size', type=int, default=DEFAULT_MAX_FILE_SIZE,
                        help=f'Maximum file size in bytes (default: {DEFAULT_MAX_FILE_SIZE})')
    parser.add_argument('--max-total-tokens', dest='max_total_tokens', type=int, default=DEFAULT_MAX_TOTAL_TOKENS,
                        help=f'Maximum total tokens (default: {DEFAULT_MAX_TOTAL_TOKENS})')
    parser.add_argument('--max-lines', dest='max_lines_per_file', type=int, default=DEFAULT_MAX_LINES_PER_FILE,
                        help=f'Maximum lines per file before summarizing (default: {DEFAULT_MAX_LINES_PER_FILE})')
    parser.add_argument('--no-content', dest='include_content', action='store_false',
                        help='Do not include file contents')
    parser.add_argument('--no-summary', dest='summarize_large_files', action='store_false',
                        help='Do not summarize large files')
    parser.add_argument('--no-parallel', dest='parallel', action='store_false',
                        help='Disable parallel processing')
    parser.add_argument('--outline-only', dest='outline_only_extensions', type=str,
                        default=','.join(DEFAULT_OUTLINE_ONLY_EXTENSIONS),
                        help='Comma-separated list of file extensions to include in outline only (default: .json,.xml,.csv,.html)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    # Convert outline_only_extensions from string to list
    if isinstance(args.outline_only_extensions, str):
        args.outline_only_extensions = [ext.strip() for ext in args.outline_only_extensions.split(',')]
        # Ensure extensions have leading dots
        args.outline_only_extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in
                                        args.outline_only_extensions]

    config = vars(args)
    scout = RepoScout(config)
    scout.export()


if __name__ == "__main__":
    main()