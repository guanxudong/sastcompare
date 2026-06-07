"""
Dataset Manager: Download and manage vulnerability test datasets.
Supports OWASP Benchmark, Juliet Test Suite, NIST SARD, and SecurityEval.
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class VulnerabilitySample:
    """Represents a single vulnerability test case."""
    sample_id: str
    language: str
    source_code: str
    file_path: str
    cwe_id: str
    cwe_name: str
    is_vulnerable: bool  # True if contains vulnerability
    vuln_type: str
    description: str
    sink_line: Optional[int] = None
    source_line: Optional[int] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DatasetStats:
    """Statistics for a loaded dataset."""
    total_samples: int
    vulnerable_count: int
    safe_count: int
    language_distribution: Dict[str, int]
    cwe_distribution: Dict[str, int]
    vuln_type_distribution: Dict[str, int]


class DatasetManager:
    """Manages vulnerability test datasets for evaluation."""
    
    SUPPORTED_LANGUAGES = ["Java", "C", "C++", "Python", "C#", "PHP", "JavaScript"]
    
    # Simulated dataset for demonstration - real implementation would download from sources
    SAMPLE_VULNERABILITIES = {
        "Java": [
            {
                "id": "JAVA-SQLI-001",
                "cwe": "CWE-89",
                "type": "SQL Injection",
                "vulnerable": True,
                "description": "Unsanitized user input concatenated into SQL query",
                "sink_line": 15,
                "code": '''import java.sql.*;
import javax.servlet.*;

public class UserAuth {
    public boolean login(String username, String password) {
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
            stmt = conn.createStatement();
            // VULNERABLE: Direct concatenation of user input
            String query = "SELECT * FROM users WHERE username='" + username + 
                          "' AND password='" + password + "'";
            ResultSet rs = stmt.executeQuery(query);
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
}'''
            },
            {
                "id": "JAVA-SQLI-002", 
                "cwe": "CWE-89",
                "type": "SQL Injection",
                "vulnerable": True,
                "description": "PreparedStatement not used properly - concatenation in setString",
                "sink_line": 12,
                "code": '''import java.sql.*;

public class ProductSearch {
    public ResultSet search(String keyword) {
        try {
            Connection conn = DB.getConnection();
            // VULNERABLE: Even with PreparedStatement, dynamic table names are unsafe
            String sql = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            return pstmt.executeQuery();
        } catch (SQLException e) {
            return null;
        }
    }
}'''
            },
            {
                "id": "JAVA-XSS-001",
                "cwe": "CWE-79",
                "type": "XSS",
                "vulnerable": True,
                "description": "Unsanitized user input reflected in HTML response",
                "sink_line": 10,
                "code": '''import javax.servlet.http.*;
import java.io.*;

public class CommentServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String comment = req.getParameter("comment");
        PrintWriter out = resp.getWriter();
        // VULNERABLE: Direct output of user input without encoding
        out.println("<html><body>");
        out.println("<p>Your comment: " + comment + "</p>");
        out.println("</body></html>");
    }
}'''
            },
            {
                "id": "JAVA-SECRETS-001",
                "cwe": "CWE-798",
                "type": "Hardcoded Secrets",
                "vulnerable": True,
                "description": "Hardcoded database password in source code",
                "sink_line": 5,
                "code": '''public class DatabaseConfig {
    private static final String DB_URL = "jdbc:mysql://prod-db.company.com:3306/app";
    private static final String DB_USER = "admin";
    // VULNERABLE: Hardcoded password
    private static final String DB_PASSWORD = "SuperSecret123!@#";
    
    public static Connection getConnection() {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}'''
            },
            {
                "id": "JAVA-PATH-001",
                "cwe": "CWE-22",
                "type": "Path Traversal",
                "vulnerable": True,
                "description": "User-controlled filename used without validation",
                "sink_line": 8,
                "code": '''import java.io.*;
import javax.servlet.http.*;

public class FileDownloadServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String filename = req.getParameter("file");
        // VULNERABLE: No path validation
        File file = new File("/app/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);
        // ... send file to response
    }
}'''
            },
            {
                "id": "JAVA-CMDI-001",
                "cwe": "CWE-78",
                "type": "Command Injection",
                "vulnerable": True,
                "description": "User input passed to Runtime.exec without sanitization",
                "sink_line": 7,
                "code": '''import java.io.*;
import javax.servlet.http.*;

public class PingServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String host = req.getParameter("host");
        // VULNERABLE: User input passed directly to command execution
        Process process = Runtime.getRuntime().exec("ping -c 4 " + host);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        // ... output result
    }
}'''
            },
            {
                "id": "JAVA-SAFE-001",
                "cwe": "CWE-89",
                "type": "SQL Injection",
                "vulnerable": False,
                "description": "Proper use of PreparedStatement with parameterized queries",
                "sink_line": None,
                "code": '''import java.sql.*;

public class SafeUserAuth {
    public boolean login(String username, String password) {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
            // SECURE: Using PreparedStatement with parameterized queries
            String query = "SELECT * FROM users WHERE username=? AND password=?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            ResultSet rs = pstmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }
}'''
            },
            {
                "id": "JAVA-SAFE-002",
                "cwe": "CWE-79",
                "type": "XSS",
                "vulnerable": False,
                "description": "User input properly encoded before output",
                "sink_line": None,
                "code": '''import javax.servlet.http.*;
import java.io.*;
import org.owasp.encoder.Encode;

public class SafeCommentServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        String comment = req.getParameter("comment");
        PrintWriter out = resp.getWriter();
        // SECURE: Encoding user input before output
        out.println("<html><body>");
        out.println("<p>Your comment: " + Encode.forHtml(comment) + "</p>");
        out.println("</body></html>");
    }
}'''
            }
        ],
        "Python": [
            {
                "id": "PY-SQLI-001",
                "cwe": "CWE-89",
                "type": "SQL Injection",
                "vulnerable": True,
                "description": "String formatting used in SQL query",
                "sink_line": 8,
                "code": '''import sqlite3
from flask import request

def get_user():
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: String formatting in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()'''
            },
            {
                "id": "PY-CMDI-001",
                "cwe": "CWE-78",
                "type": "Command Injection",
                "vulnerable": True,
                "description": "os.system called with user-controlled input",
                "sink_line": 7,
                "code": '''import os
from flask import request

def ping_host():
    host = request.args.get('host')
    # VULNERABLE: User input passed to os.system
    result = os.system(f"ping -c 4 {host}")
    return {"status": result}'''
            },
            {
                "id": "PY-SECRETS-001",
                "cwe": "CWE-798",
                "type": "Hardcoded Secrets",
                "vulnerable": True,
                "description": "API key hardcoded in Python module",
                "sink_line": 4,
                "code": '''import requests

class PaymentGateway:
    # VULNERABLE: Hardcoded API key
    API_KEY = "sk_live_TEST_DUMMY_KEY_FOR_SAST_POC"
    BASE_URL = "https://api.payment.com/v1"
    
    def charge(self, amount, card_token):
        headers = {"Authorization": f"Bearer {self.API_KEY}"}
        data = {"amount": amount, "card": card_token}
        return requests.post(f"{self.BASE_URL}/charges", 
                           json=data, headers=headers)'''
            },
            {
                "id": "PY-SSRF-001",
                "cwe": "CWE-918",
                "type": "SSRF",
                "vulnerable": True,
                "description": "User-controlled URL used in server-side request",
                "sink_line": 7,
                "code": '''import requests
from flask import request

def fetch_url():
    url = request.args.get('url')
    # VULNERABLE: No URL validation - can access internal services
    response = requests.get(url, timeout=30)
    return response.text'''
            },
            {
                "id": "PY-SAFE-001",
                "cwe": "CWE-89",
                "type": "SQL Injection",
                "vulnerable": False,
                "description": "Parameterized query with sqlite3",
                "sink_line": None,
                "code": '''import sqlite3
from flask import request

def get_user_safe():
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SECURE: Using parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()'''
            },
            {
                "id": "PY-SAFE-002",
                "cwe": "CWE-78",
                "type": "Command Injection",
                "vulnerable": False,
                "description": "Using subprocess with argument list instead of shell",
                "sink_line": None,
                "code": '''import subprocess
from flask import request

def ping_host_safe():
    host = request.args.get('host')
    # SECURE: Using list of arguments - no shell interpretation
    result = subprocess.run(
        ["ping", "-c", "4", host],
        capture_output=True,
        text=True
    )
    return {"output": result.stdout}'''
            }
        ],
        "C": [
            {
                "id": "C-BUF-001",
                "cwe": "CWE-121",
                "type": "Buffer Overflow",
                "vulnerable": True,
                "description": "strcpy used without bounds checking",
                "sink_line": 6,
                "code": '''#include <string.h>
#include <stdio.h>

void process_input(char *user_input) {
    char buffer[64];
    // VULNERABLE: strcpy doesn't check buffer bounds
    strcpy(buffer, user_input);
    printf("Processed: %s\\n", buffer);
}'''
            },
            {
                "id": "C-FMT-001",
                "cwe": "CWE-134",
                "type": "Format String",
                "vulnerable": True,
                "description": "User input passed as format string to printf",
                "sink_line": 5,
                "code": '''#include <stdio.h>

void log_message(char *user_msg) {
    // VULNERABLE: User input used as format string
    printf(user_msg);
}'''
            }
        ]
    }
    
    def __init__(self, base_path: str = "./datasets"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(exist_ok=True)
        self.samples: List[VulnerabilitySample] = []
        
    def load_simulated_dataset(self, languages: Optional[List[str]] = None) -> DatasetStats:
        """Load simulated vulnerability samples for demonstration."""
        if languages is None:
            languages = self.SUPPORTED_LANGUAGES
            
        self.samples = []
        for lang in languages:
            if lang in self.SAMPLE_VULNERABILITIES:
                for item in self.SAMPLE_VULNERABILITIES[lang]:
                    sample = VulnerabilitySample(
                        sample_id=item["id"],
                        language=lang,
                        source_code=item["code"],
                        file_path=f"{lang.lower()}/{item['id']}.{self._get_extension(lang)}",
                        cwe_id=item["cwe"],
                        cwe_name=self._get_cwe_name(item["cwe"]),
                        is_vulnerable=item["vulnerable"],
                        vuln_type=item["type"],
                        description=item["description"],
                        sink_line=item.get("sink_line")
                    )
                    self.samples.append(sample)
        
        return self.get_stats()
    
    def _get_extension(self, language: str) -> str:
        """Get file extension for language."""
        mapping = {
            "Java": "java", "C": "c", "C++": "cpp",
            "Python": "py", "C#": "cs", "PHP": "php",
            "JavaScript": "js"
        }
        return mapping.get(language, "txt")
    
    def _get_cwe_name(self, cwe_id: str) -> str:
        """Get CWE name from ID."""
        cwe_map = {
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-22": "Path Traversal",
            "CWE-78": "OS Command Injection",
            "CWE-94": "Code Injection",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-121": "Stack-based Buffer Overflow",
            "CWE-134": "Uncontrolled Format String",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
            "CWE-20": "Improper Input Validation",
            "CWE-200": "Information Exposure"
        }
        return cwe_map.get(cwe_id, "Unknown CWE")
    
    def get_stats(self) -> DatasetStats:
        """Calculate dataset statistics."""
        total = len(self.samples)
        vulnerable = sum(1 for s in self.samples if s.is_vulnerable)
        safe = total - vulnerable
        
        lang_dist = {}
        cwe_dist = {}
        vuln_type_dist = {}
        
        for s in self.samples:
            lang_dist[s.language] = lang_dist.get(s.language, 0) + 1
            cwe_dist[s.cwe_id] = cwe_dist.get(s.cwe_id, 0) + 1
            vuln_type_dist[s.vuln_type] = vuln_type_dist.get(s.vuln_type, 0) + 1
            
        return DatasetStats(
            total_samples=total,
            vulnerable_count=vulnerable,
            safe_count=safe,
            language_distribution=lang_dist,
            cwe_distribution=cwe_dist,
            vuln_type_distribution=vuln_type_dist
        )
    
    def get_samples_by_language(self, language: str) -> List[VulnerabilitySample]:
        """Get samples filtered by programming language."""
        return [s for s in self.samples if s.language == language]
    
    def get_samples_by_cwe(self, cwe_id: str) -> List[VulnerabilitySample]:
        """Get samples filtered by CWE ID."""
        return [s for s in self.samples if s.cwe_id == cwe_id]
    
    def get_samples_by_type(self, vuln_type: str) -> List[VulnerabilitySample]:
        """Get samples filtered by vulnerability type."""
        return [s for s in self.samples if s.vuln_type == vuln_type]
    
    def export_to_files(self) -> Dict[str, str]:
        """Export samples to source files organized by language."""
        export_paths = {}
        
        for sample in self.samples:
            lang_dir = self.base_path / sample.language.lower()
            lang_dir.mkdir(exist_ok=True)
            
            file_path = lang_dir / f"{sample.sample_id}.{self._get_extension(sample.language)}"
            with open(file_path, 'w') as f:
                f.write(f"// CWE: {sample.cwe_id} - {sample.cwe_name}\n")
                f.write(f"// Type: {sample.vuln_type}\n")
                f.write(f"// Vulnerable: {sample.is_vulnerable}\n")
                f.write(f"// Description: {sample.description}\n")
                f.write(sample.source_code)
            
            export_paths[sample.sample_id] = str(file_path)
            
        return export_paths
    
    def save_metadata(self, filepath: str = "./datasets/metadata.json"):
        """Save dataset metadata to JSON."""
        stats = self.get_stats()
        metadata = {
            "stats": {
                "total_samples": stats.total_samples,
                "vulnerable_count": stats.vulnerable_count,
                "safe_count": stats.safe_count,
                "language_distribution": stats.language_distribution,
                "cwe_distribution": stats.cwe_distribution,
                "vuln_type_distribution": stats.vuln_type_distribution
            },
            "samples": [s.to_dict() for s in self.samples]
        }
        
        with open(filepath, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Dataset metadata saved to {filepath}")


if __name__ == "__main__":
    # Test the dataset manager
    dm = DatasetManager()
    stats = dm.load_simulated_dataset()
    print(f"Loaded {stats.total_samples} samples")
    print(f"Vulnerable: {stats.vulnerable_count}, Safe: {stats.safe_count}")
    print(f"Languages: {stats.language_distribution}")
    dm.export_to_files()
    dm.save_metadata()
