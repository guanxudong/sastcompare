/**
 * Dataset Manager: Download and manage vulnerability test datasets.
 * Supports OWASP Benchmark, Juliet Test Suite, NIST SARD, and SecurityEval.
 */
import * as fs from "fs/promises";
import * as path from "path";
import { VulnerabilitySample, DatasetStats } from "./types";

const SUPPORTED_LANGUAGES = ["Java", "C", "C++", "Python", "C#", "PHP", "JavaScript"];

const EXTENSION_MAP: Record<string, string> = {
  Java: "java",
  C: "c",
  "C++": "cpp",
  Python: "py",
  "C#": "cs",
  PHP: "php",
  JavaScript: "js",
};

const CWE_NAME_MAP: Record<string, string> = {
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
  "CWE-200": "Information Exposure",
};

interface SampleData {
  id: string;
  cwe: string;
  type: string;
  vulnerable: boolean;
  description: string;
  sink_line?: number;
  code: string;
}

const SAMPLE_VULNERABILITIES: Record<string, SampleData[]> = {
  Java: [
    {
      id: "JAVA-SQLI-001",
      cwe: "CWE-89",
      type: "SQL Injection",
      vulnerable: true,
      description: "Unsanitized user input concatenated into SQL query",
      sink_line: 15,
      code: `import java.sql.*;
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
}`,
    },
    {
      id: "JAVA-SQLI-002",
      cwe: "CWE-89",
      type: "SQL Injection",
      vulnerable: true,
      description: "PreparedStatement not used properly - concatenation in setString",
      sink_line: 12,
      code: `import java.sql.*;

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
}`,
    },
    {
      id: "JAVA-XSS-001",
      cwe: "CWE-79",
      type: "XSS",
      vulnerable: true,
      description: "Unsanitized user input reflected in HTML response",
      sink_line: 10,
      code: `import javax.servlet.http.*;
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
}`,
    },
    {
      id: "JAVA-SECRETS-001",
      cwe: "CWE-798",
      type: "Hardcoded Secrets",
      vulnerable: true,
      description: "Hardcoded database password in source code",
      sink_line: 5,
      code: `public class DatabaseConfig {
    private static final String DB_URL = "jdbc:mysql://prod-db.company.com:3306/app";
    private static final String DB_USER = "admin";
    // VULNERABLE: Hardcoded password
    private static final String DB_PASSWORD = "SuperSecret123!@#";
    
    public static Connection getConnection() {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}`,
    },
    {
      id: "JAVA-PATH-001",
      cwe: "CWE-22",
      type: "Path Traversal",
      vulnerable: true,
      description: "User-controlled filename used without validation",
      sink_line: 8,
      code: `import java.io.*;
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
}`,
    },
    {
      id: "JAVA-CMDI-001",
      cwe: "CWE-78",
      type: "Command Injection",
      vulnerable: true,
      description: "User input passed to Runtime.exec without sanitization",
      sink_line: 7,
      code: `import java.io.*;
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
}`,
    },
    {
      id: "JAVA-SAFE-001",
      cwe: "CWE-89",
      type: "SQL Injection",
      vulnerable: false,
      description: "Proper use of PreparedStatement with parameterized queries",
      code: `import java.sql.*;

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
}`,
    },
    {
      id: "JAVA-SAFE-002",
      cwe: "CWE-79",
      type: "XSS",
      vulnerable: false,
      description: "User input properly encoded before output",
      code: `import javax.servlet.http.*;
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
}`,
    },
  ],
  Python: [
    {
      id: "PY-SQLI-001",
      cwe: "CWE-89",
      type: "SQL Injection",
      vulnerable: true,
      description: "String formatting used in SQL query",
      sink_line: 8,
      code: `import sqlite3
from flask import request

def get_user():
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    // VULNERABLE: String formatting in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()`,
    },
    {
      id: "PY-CMDI-001",
      cwe: "CWE-78",
      type: "Command Injection",
      vulnerable: true,
      description: "os.system called with user-controlled input",
      sink_line: 7,
      code: `import os
from flask import request

def ping_host():
    host = request.args.get('host')
    // VULNERABLE: User input passed to os.system
    result = os.system(f"ping -c 4 {host}")
    return {"status": result}`,
    },
    {
      id: "PY-SECRETS-001",
      cwe: "CWE-798",
      type: "Hardcoded Secrets",
      vulnerable: true,
      description: "API key hardcoded in Python module",
      sink_line: 4,
      code: `import requests

class PaymentGateway:
    // VULNERABLE: Hardcoded API key
    API_KEY = "sk_live_TEST_DUMMY_KEY_FOR_SAST_POC"
    BASE_URL = "https://api.payment.com/v1"
    
    def charge(self, amount, card_token):
        headers = {"Authorization": f"Bearer {self.API_KEY}"}
        data = {"amount": amount, "card": card_token}
        return requests.post(f"{self.BASE_URL}/charges", 
                           json=data, headers=headers)`,
    },
    {
      id: "PY-SSRF-001",
      cwe: "CWE-918",
      type: "SSRF",
      vulnerable: true,
      description: "User-controlled URL used in server-side request",
      sink_line: 7,
      code: `import requests
from flask import request

def fetch_url():
    url = request.args.get('url')
    // VULNERABLE: No URL validation - can access internal services
    response = requests.get(url, timeout=30)
    return response.text`,
    },
    {
      id: "PY-SAFE-001",
      cwe: "CWE-89",
      type: "SQL Injection",
      vulnerable: false,
      description: "Parameterized query with sqlite3",
      code: `import sqlite3
from flask import request

def get_user_safe():
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    // SECURE: Using parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()`,
    },
    {
      id: "PY-SAFE-002",
      cwe: "CWE-78",
      type: "Command Injection",
      vulnerable: false,
      description: "Using subprocess with argument list instead of shell",
      code: `import subprocess
from flask import request

def ping_host_safe():
    host = request.args.get('host')
    // SECURE: Using list of arguments - no shell interpretation
    result = subprocess.run(
        ["ping", "-c", "4", host],
        capture_output=True,
        text=True
    )
    return {"output": result.stdout}`,
    },
  ],
  C: [
    {
      id: "C-BUF-001",
      cwe: "CWE-121",
      type: "Buffer Overflow",
      vulnerable: true,
      description: "strcpy used without bounds checking",
      sink_line: 6,
      code: `#include <string.h>
#include <stdio.h>

void process_input(char *user_input) {
    char buffer[64];
    // VULNERABLE: strcpy doesn't check buffer bounds
    strcpy(buffer, user_input);
    printf("Processed: %s\\n", buffer);
}`,
    },
    {
      id: "C-FMT-001",
      cwe: "CWE-134",
      type: "Format String",
      vulnerable: true,
      description: "User input passed as format string to printf",
      sink_line: 5,
      code: `#include <stdio.h>

void log_message(char *user_msg) {
    // VULNERABLE: User input used as format string
    printf(user_msg);
}`,
    },
  ],
};

export class DatasetManager {
  private basePath: string;
  public samples: VulnerabilitySample[] = [];

  constructor(basePath: string = "./datasets") {
    this.basePath = basePath;
  }

  async loadSimulatedDataset(languages?: string[]): Promise<DatasetStats> {
    const langs = languages || SUPPORTED_LANGUAGES;
    this.samples = [];

    for (const lang of langs) {
      const items = SAMPLE_VULNERABILITIES[lang];
      if (items) {
        for (const item of items) {
          const sample: VulnerabilitySample = {
            sample_id: item.id,
            language: lang,
            source_code: item.code,
            file_path: `${lang.toLowerCase()}/${item.id}.${EXTENSION_MAP[lang] || "txt"}`,
            cwe_id: item.cwe,
            cwe_name: CWE_NAME_MAP[item.cwe] || "Unknown CWE",
            is_vulnerable: item.vulnerable,
            vuln_type: item.type,
            description: item.description,
            sink_line: item.sink_line,
          };
          this.samples.push(sample);
        }
      }
    }

    return this.getStats();
  }

  getStats(): DatasetStats {
    const total = this.samples.length;
    const vulnerable = this.samples.filter((s) => s.is_vulnerable).length;
    const safe = total - vulnerable;

    const langDist: Record<string, number> = {};
    const cweDist: Record<string, number> = {};
    const vulnTypeDist: Record<string, number> = {};

    for (const s of this.samples) {
      langDist[s.language] = (langDist[s.language] || 0) + 1;
      cweDist[s.cwe_id] = (cweDist[s.cwe_id] || 0) + 1;
      vulnTypeDist[s.vuln_type] = (vulnTypeDist[s.vuln_type] || 0) + 1;
    }

    return {
      total_samples: total,
      vulnerable_count: vulnerable,
      safe_count: safe,
      language_distribution: langDist,
      cwe_distribution: cweDist,
      vuln_type_distribution: vulnTypeDist,
    };
  }

  getSamplesByLanguage(language: string): VulnerabilitySample[] {
    return this.samples.filter((s) => s.language === language);
  }

  getSamplesByCwe(cweId: string): VulnerabilitySample[] {
    return this.samples.filter((s) => s.cwe_id === cweId);
  }

  getSamplesByType(vulnType: string): VulnerabilitySample[] {
    return this.samples.filter((s) => s.vuln_type === vulnType);
  }

  async exportToFiles(): Promise<Record<string, string>> {
    const exportPaths: Record<string, string> = {};

    for (const sample of this.samples) {
      const langDir = path.join(this.basePath, sample.language.toLowerCase());
      await fs.mkdir(langDir, { recursive: true });

      const ext = EXTENSION_MAP[sample.language] || "txt";
      const filePath = path.join(langDir, `${sample.sample_id}.${ext}`);
      const content = `// CWE: ${sample.cwe_id} - ${sample.cwe_name}\n// Type: ${sample.vuln_type}\n// Vulnerable: ${sample.is_vulnerable}\n// Description: ${sample.description}\n${sample.source_code}`;

      await fs.writeFile(filePath, content, "utf-8");
      exportPaths[sample.sample_id] = filePath;
    }

    return exportPaths;
  }

  async saveMetadata(filepath: string = "./datasets/metadata.json"): Promise<void> {
    const stats = this.getStats();
    const metadata = {
      stats: {
        total_samples: stats.total_samples,
        vulnerable_count: stats.vulnerable_count,
        safe_count: stats.safe_count,
        language_distribution: stats.language_distribution,
        cwe_distribution: stats.cwe_distribution,
        vuln_type_distribution: stats.vuln_type_distribution,
      },
      samples: this.samples,
    };

    await fs.mkdir(path.dirname(filepath), { recursive: true });
    await fs.writeFile(filepath, JSON.stringify(metadata, null, 2), "utf-8");
    console.log(`Dataset metadata saved to ${filepath}`);
  }
}
