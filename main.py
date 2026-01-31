
from core.engine import DASTEngine
import json
import datetime
import os


class AutomatedScanner:
    def __init__(self, engine_config=None):
        """
        engine_config: dict
          - auth_enabled, login_url, auth_username_param, auth_password_param,
            auth_test_user, auth_test_pass, max_pages, etc.
        """
        self.engine = DASTEngine(config=engine_config or {})

    def full_website_scan(self, start_url, max_pages=4):
        print(f"🎯 Starting full website scan: {start_url}")
        print("=" * 60)

        # Phase 1: Smart scanning
        print("🔍 Phase 1: Smart Scanning...")
        scan_report = self.engine.quick_scan(start_url, max_pages=max_pages)

        # Extract data from engine's report
        discovered_urls = [vuln["url"] for vuln in scan_report["vulnerabilities"]]
        all_vulnerabilities = scan_report["vulnerabilities"]

        print(f"✅ Scanned {scan_report['crawled_pages']} pages")
        print(f"✅ Found {len(discovered_urls)} unique URLs")

        # Phase 2: Report generate
        print("\n📊 Phase 2: Generating Report...")
        report = self.generate_report(start_url, discovered_urls, all_vulnerabilities)

        return report

    def generate_report(self, start_url, discovered_urls, vulnerabilities):
        """
        Professional report generate
        """
        vuln_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln["type"]
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)

        report = {
            "scan_summary": {
                "target_website": start_url,
                "urls_discovered": len(discovered_urls),
                "urls_scanned": len(discovered_urls),
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerability_breakdown": {
                    k: len(v) for k, v in vuln_by_type.items()
                },
            },
            "discovered_urls": discovered_urls,
            "vulnerabilities": vulnerabilities,
            "vulnerabilities_by_type": vuln_by_type,
        }

        self.display_console_report(report)
        self.save_report_to_file(report, start_url)

        return report

    def display_console_report(self, report):
        """
        Display beautiful report in console
        """
        summary = report["scan_summary"]

        print("\n" + "=" * 60)
        print("🎯 DAST SCAN COMPLETE REPORT")
        print("=" * 60)
        print(f"🌐 Website: {summary['target_website']}")
        print(f"📄 URLs Discovered: {summary['urls_discovered']}")
        print(f"🔍 URLs Scanned: {summary['urls_scanned']}")
        print(f"⚠️ Total Vulnerabilities: {summary['total_vulnerabilities']}")

        print("\n📊 Vulnerability Breakdown:")
        for vuln_type, count in summary["vulnerability_breakdown"].items():
            print(f"   ✅ {vuln_type}: {count}")

        # Top vulnerable URLs
        vulnerabilities = report["vulnerabilities"]
        if vulnerabilities:
            print("\n🔍 Top Vulnerable URLs:")
            vulnerable_urls = {}
            for vuln in vulnerabilities:
                url = vuln["url"]
                if url not in vulnerable_urls:
                    vulnerable_urls[url] = 0
                vulnerable_urls[url] += 1

            sorted_urls = sorted(
                vulnerable_urls.items(), key=lambda x: x[1], reverse=True
            )[:5]

            for url, count in sorted_urls:
                print(f"🔴 {url} - {count} vulnerabilities")

    def save_report_to_file(self, report, start_url):
        """
        Report file mein save karein (dast_report folder ke andar)
        """
        reports_dir = "dast_report"
        os.makedirs(reports_dir, exist_ok=True)

        safe_filename = (
            start_url.replace("://", "_")
            .replace("/", "_")
            .replace(":", "_")
            .replace("?", "_")
            .replace("&", "_")
        )
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{safe_filename}_{timestamp}.json"

        filepath = os.path.join(reports_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(f"\n💾 Report saved to: {filepath}")


def main():
    """
    CLI test ke liye
    """
    engine_config = {
        # yahan auth config optional hai; backend se aayega
        # "auth_enabled": True,
        # "login_url": "https://target.com/login",
        # "auth_username_param": "email",
        # "auth_password_param": "password",
        # "auth_test_user": "testuser@example.com",
        # "auth_test_pass": "Test@123",
    }
    scanner = AutomatedScanner(engine_config=engine_config)

    websites_to_scan = [
        #"https://owasp.org/www-project-juice-shop/",
        #"http://testphp.vulnweb.com/artists.php?artist=1"
        #"https://e-commerce-frontend-alpha-opal.vercel.app/"
         #"http://testphp.vulnweb.com",
         # "http://demo.testfire.net", 
    ]

    for website in websites_to_scan:
        print(f"\n{'=' * 50}")
        print(f"🎯 Scanning: {website}")
        print("=" * 50)

        try:
            report = scanner.full_website_scan(website, max_pages=2)
            if report["scan_summary"]["total_vulnerabilities"] > 0:
                print(f"\n🔍 Sample Vulnerabilities for {website}:")
                for i, vuln in enumerate(report["vulnerabilities"][:3], 1):
                    print(f"   {i}. {vuln['type']} - {vuln.get('parameter', 'N/A')}")
                    print(f"      URL: {vuln['url']}")
        except Exception as e:
            print(f"❌ Error scanning {website}: {e}")


if __name__ == "__main__":
    main()
