# About Security Report Viewer

Security Report Viewer is an open-source, lightweight security monitoring and log analysis application designed to help system administrators, developers and server operators identify, investigate and understand suspicious activities within their Linux server environments.

Built with Rust for performance, reliability and memory safety, the application integrates a security log scanner with an interactive, browser-based reporting dashboard. It transforms complex system logs into structured, readable and actionable security reports, making security investigations more efficient and accessible.

The application provides:

- Integrated security scanning of Linux system logs.
- Detection of suspicious activities, including SQL injection attempts, brute-force attacks and malicious web requests.
- IP address correlation and threat severity classification.
- Interactive investigation dashboards with searching, filtering, sorting and pagination.
- Support for importing existing TXT and JSON security reports.
- Security scan coverage and diagnostic information.
- Saved report management and printable reports.
- Private remote server access through encrypted SSH tunnels.
- Automated deployment updates with verification and rollback capabilities (proposed in [pull request #8](https://github.com/YusainiU/Security-Report-Viewer/pull/8); pending merge and live testing at the time of writing).

Security Report Viewer is designed with simplicity, privacy and operational security in mind. It requires no external database, third-party analytics services or cloud-based processing. Security reports remain within the user's own environment unless explicitly shared.

The application is intended to complement existing security measures, rather than replace firewalls, intrusion detection systems or professional security assessments.

Released under the [GNU General Public License v3.0](LICENCE), Security Report Viewer encourages open collaboration, transparency and continuous improvement.

**Understand your logs. Identify suspicious activity. Strengthen your server security.**
