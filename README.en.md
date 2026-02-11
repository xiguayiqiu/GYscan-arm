# Gyscan-ARM Exploit Database

## Project Overview

Gyscan-ARM is a professional database project dedicated to collecting and organizing various security exploit codes. This project includes exploit codes targeting different operating systems, web applications, and embedded devices, providing comprehensive exploit resources for security researchers, penetration testers, and vulnerability analysts.

The project employs a structured directory organization system, categorizing and storing exploit codes by target platform (Platform), attack type (Type), and file format, enabling users to quickly search and locate required exploit code. All collected exploit codes are sourced from publicly available security research communities and are intended solely for legitimate security testing and research activities.

## Key Features

This project features the following core capabilities:

- **Comprehensive Classification System**: Covers mainstream platforms and application types including AIX, Android, ARM, ASP, ASPX, BSD, CFM, CGI, and more.
- **Extensive Attack Types**: Supports multiple attack scenarios such as Local privilege escalation, Remote exploitation, Denial of Service (DoS), and Web application attacks (Webapps).
- **Broad Format Support**: Accommodates exploit codes written in multiple programming languages and scripting formats, including Python, Ruby, C/C++, Perl, PHP, Shell, and Bash.

## Directory Structure

The primary directory structure under the project root is as follows:

```
gyscan-arm/
├── Client/                    # Client tools directory
│   ├── app.ico               # Application icon
│   ├── app.png               # Application icon
│   ├── build.sh              # Build script
│   ├── dirmap/               # Directory mapping configuration
│   │   ├── dicc.txt          # Dictionary file
│   │   └── medium.txt        # Medium-sized dictionary file
│   └── exploitdb/            # Core exploit database directory
│       ├── exploits/         # Main directory for exploit codes
│       │   ├── aix/          # AIX system exploits
│       │   │   ├── dos/      # Denial of Service attacks
│       │   │   ├── local/    # Local privilege escalation exploits
│       │   │   ├── remote/   # Remote exploitation exploits
│       │   │   └── webapps/  # Web application vulnerabilities
│       │   ├── android/      # Android system exploits
│       │   │   ├── dos/
│       │   │   ├── local/
│       │   │   ├── remote/
│       │   │   └── webapps/
│       │   ├── arm/          # ARM architecture exploits
│       │   ├── asp/          # ASP application exploits
│       │   ├── aspx/         # ASP.NET application exploits
│       │   ├── bsd/          # BSD system exploits
│       │   ├── cfm/          # ColdFusion exploits
│       │   ├── cgi/          # CGI script exploits
│       │   └── ...           # Other platforms
│       └── LICENSE.md        # License file
```

## Usage Instructions

### Environment Preparation

The exploit codes in this project involve multiple programming languages and environments. We recommend setting up the following runtime environments:

- For Python scripts: Python 2.7 or Python 3.x is required; some scripts may require additional dependencies such as `requests` or `cherrypy`.
- For Ruby scripts: A Ruby runtime environment with the Metasploit framework is recommended.
- For C/C++ code: Compilers such as GCC or Clang, along with appropriate build tools, are required.
- For Perl scripts: A Perl interpreter and relevant modules are necessary.

### Searching for Exploit Codes

Users can locate relevant exploit codes by navigating to the corresponding platform directory based on the target system and application type. For example, to find local privilege escalation exploits for Android, navigate to `Client/exploitdb/exploits/android/local/`. Filenames typically follow the format `vulnerability_id.extension`, such as `35711.c`, indicating a C-language exploit with ID 35711.

### Code Usage Notes

When using exploit codes from this project, please observe the following guidelines:

- Only test on systems for which you have explicit authorization.
- Carefully read all comments and documentation within the code to understand its conditions and limitations.
- Some exploit codes may require parameter adjustments to suit the target environment.
- Before actual deployment, always test functionality in an isolated, controlled environment.

## Platform Coverage

This project currently supports the following platforms and attack types, among others:

**Operating Systems**: AIX, Android, ARM, BSD (FreeBSD, OpenBSD, NetBSD), Linux, Solaris, Windows, and other mainstream operating systems.

**Web Application Technologies**: ASP, ASP.NET, PHP, ColdFusion, CGI, Java Servlet, and other web application stacks.

**Attack Vectors**: Local privilege escalation, remote code execution, SQL injection, cross-site scripting (XSS), file upload vulnerabilities, command injection, authentication bypass, and other vulnerability types.

## Contributing

Security researchers are welcome to contribute exploit codes to this project. When contributing, ensure code completeness and executability, and include necessary documentation. Before submission, place your code in the appropriate subdirectory under the existing directory structure corresponding to the target platform and attack type.

## License

For specific licensing information, please refer to the `Client/exploitdb/LICENSE.md` file. When using any exploit code included in this project, strictly adhere to the terms of the applicable license.

## Disclaimer

This project is intended solely for security research and educational purposes. Users are solely responsible for ensuring their activities comply with applicable local laws, regulations, and ethical standards. The project maintainers assume no liability for any consequences arising from misuse of the code contained herein.